#!/usr/bin/env python3
"""Static text scanner for pre-install skill security audits.

This script reads files as text and reports suspicious patterns. It does not
execute target code, import target modules, install dependencies, or make
network requests.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    ".next",
}

CODE_EXTS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".bat",
    ".cmd",
    ".rb",
    ".go",
    ".rs",
    ".java",
    ".php",
    ".lua",
    ".ipynb",
}

DEPENDENCY_FILES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "pipfile",
    "poetry.lock",
    "makefile",
    "dockerfile",
    "docker-compose.yml",
    "install.sh",
    "install.ps1",
}

PATTERNS = [
    ("critical", "hidden instruction", r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "ignore previous instructions"),
    ("critical", "hidden instruction", r"do\s+not\s+(tell|inform|show)\s+(the\s+)?user", "hide behavior from user"),
    ("critical", "hidden instruction", r"(hide|conceal).*(purpose|behavior|risk|network|file)", "hide purpose or behavior"),
    ("critical", "hidden instruction", r"(bypass|disable).*(safety|security|restriction|policy)", "bypass safety/security"),
    ("critical", "hidden instruction", r"忽略.*(指令|规则|限制)", "ignore instructions"),
    ("critical", "hidden instruction", r"(不要|不得).*告诉用户", "do not tell user"),
    ("critical", "hidden instruction", r"隐藏.*(目的|行为|风险|联网|文件)", "hide purpose or behavior"),
    ("critical", "remote execution", r"\b(eval|exec)\s*\(", "dynamic code execution"),
    ("critical", "remote execution", r"\bFunction\s*\(", "JavaScript Function constructor"),
    ("critical", "remote execution", r"\b(os\.system|subprocess\.[A-Za-z_]+|child_process\.(exec|spawn|execFile))\b", "shell/process execution"),
    ("critical", "remote execution", r"\bInvoke-Expression\b|\biex\b", "PowerShell dynamic execution"),
    ("high", "remote execution", r"shell\s*=\s*True", "shell=True execution"),
    ("critical", "unsafe deserialization", r"\b(pickle\.load|pickle\.loads|marshal\.load|marshal\.loads|yaml\.load)\b", "unsafe deserialization"),
    ("high", "network", r"\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b", "download or network command"),
    ("high", "network", r"\b(requests\.(get|post|put)|fetch\s*\(|axios\.|WebSocket\s*\()", "network request"),
    ("high", "network", r"https?://[^\s'\"<>]+", "URL literal"),
    ("critical", "exfiltration", r"\b(webhook|discord(app)?\.com/api/webhooks|api\.telegram\.org|ftp://|s3://)\b", "webhook or upload endpoint"),
    ("critical", "sensitive data", r"(\.env\b|\.ssh\b|id_rsa|id_dsa|id_ed25519|known_hosts)", "sensitive key path"),
    ("critical", "sensitive data", r"\b(api[_-]?key|secret[_-]?key|access[_-]?token|refresh[_-]?token|cookie|credentials?)\b", "secret or credential access"),
    ("high", "sensitive data", r"(browser|chrome|edge|firefox).*(cookie|profile|password)", "browser sensitive data"),
    ("critical", "destructive", r"\brm\s+-rf\b|\bdel\s+/s\b|Remove-Item\b.*-Recurse|shutil\.rmtree", "recursive deletion"),
    ("critical", "destructive", r"\b(cipher|encrypt|decrypt)\b.*\b(file|folder|directory|path)\b", "file encryption operation"),
    ("critical", "persistence", r"\b(crontab|systemd|LaunchAgent|schtasks|Startup|RunOnce)\b", "persistence mechanism"),
    ("high", "system modification", r"\b(reg\s+add|Set-ItemProperty|chmod\s+777|sudo\b)", "system or permission modification"),
    ("high", "install hook", r"\b(preinstall|postinstall|prepare|pip\s+install|npm\s+install|yarn\s+install)\b", "install hook or package install"),
    ("high", "auto update", r"\b(git\s+pull|git\s+clone|auto-?update|self-?update)\b", "remote update behavior"),
    ("high", "obfuscation", r"(base64\.b64decode|atob\s*\(|fromCharCode|Buffer\.from\s*\([^)]*base64)", "base64 decode"),
    ("high", "obfuscation", r"(\\x[0-9a-fA-F]{2}){8,}", "long hex escape string"),
    ("medium", "obfuscation", r"[A-Za-z0-9+/]{120,}={0,2}", "long encoded-looking string"),
]


@dataclass
class Finding:
    level: str
    category: str
    file: str
    line: int
    pattern: str
    snippet: str


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def collect_files(root: Path, include_vendor: bool) -> tuple[list[Path], list[tuple[str, str]]]:
    skipped: list[tuple[str, str]] = []
    if root.is_file():
        return [root], skipped

    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        kept_dirs: list[str] = []
        for dirname in dirnames:
            directory = current / dirname
            if directory.is_symlink():
                skipped.append((rel(directory, root), "symlink directory"))
            elif not include_vendor and dirname in SKIP_DIRS:
                skipped.append((rel(directory, root), "skipped directory"))
            else:
                kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in filenames:
            file_path = current / filename
            if file_path.is_symlink():
                skipped.append((rel(file_path, root), "symlink file"))
            else:
                files.append(file_path)

    return files, skipped


def is_binary(data: bytes) -> bool:
    return b"\x00" in data[:4096]


def classify(path: Path) -> str:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if name in {"skill.md", "readme.md"} or "prompt" in name:
        return "prompt/docs"
    if suffix in CODE_EXTS:
        return "code"
    if name in DEPENDENCY_FILES:
        return "dependency/install"
    if suffix in {".yaml", ".yml", ".json", ".toml", ".cfg", ".ini"}:
        return "config"
    if suffix in {".exe", ".dll", ".so", ".dylib", ".bin"}:
        return "binary"
    return "other"


def scan_file(path: Path, root: Path, max_bytes: int, regexes: list[tuple[str, str, re.Pattern[str], str]]) -> tuple[list[Finding], str | None]:
    try:
        stat = path.stat()
    except OSError as exc:
        return [], f"stat failed: {exc}"

    if stat.st_size > max_bytes:
        return [], f"larger than max_bytes ({stat.st_size} > {max_bytes})"

    try:
        data = path.read_bytes()
    except OSError as exc:
        return [], f"read failed: {exc}"

    if is_binary(data):
        return [], "binary-like content"

    text = data.decode("utf-8", errors="replace")
    findings: list[Finding] = []
    relative = rel(path, root)

    for line_number, line in enumerate(text.splitlines(), 1):
        for level, category, regex, label in regexes:
            if regex.search(line):
                snippet = re.sub(r"\s+", " ", line.strip())
                if len(snippet) > 180:
                    snippet = snippet[:177] + "..."
                findings.append(Finding(level, category, relative, line_number, label, snippet))

    return findings, None


def md_cell(value: object) -> str:
    text = str(value).replace("|", "\\|").replace("\n", " ")
    return text


def print_markdown(target: Path, files: list[Path], skipped: list[tuple[str, str]], findings: list[Finding], root: Path) -> None:
    counts: dict[str, int] = {}
    for file_path in files:
        kind = classify(file_path)
        counts[kind] = counts.get(kind, 0) + 1

    print("# Static Skill Scan")
    print()
    print(f"Target: `{target}`")
    print(f"Files discovered: {len(files)}")
    print(f"Skipped entries: {len(skipped)}")
    print()
    print("## File Inventory")
    print()
    print("| Type | Count |")
    print("| -- | --: |")
    for kind in sorted(counts):
        print(f"| {md_cell(kind)} | {counts[kind]} |")

    priority = [p for p in files if classify(p) in {"prompt/docs", "code", "dependency/install", "config", "binary"}]
    if priority:
        print()
        print("## Priority Files")
        print()
        print("| File | Type |")
        print("| -- | -- |")
        for file_path in sorted(priority, key=lambda p: rel(p, root).lower())[:200]:
            print(f"| `{md_cell(rel(file_path, root))}` | {md_cell(classify(file_path))} |")
        if len(priority) > 200:
            print(f"| ... | {len(priority) - 200} more priority files omitted |")

    print()
    print("## Findings")
    print()
    if not findings:
        print("No suspicious keyword findings. This does not prove the target is safe; continue manual review.")
    else:
        print("| Level | Category | File | Line | Pattern | Snippet |")
        print("| -- | -- | -- | --: | -- | -- |")
        for finding in findings[:300]:
            print(
                f"| {md_cell(finding.level)} | {md_cell(finding.category)} | "
                f"`{md_cell(finding.file)}` | {finding.line} | {md_cell(finding.pattern)} | {md_cell(finding.snippet)} |"
            )
        if len(findings) > 300:
            print(f"| ... | ... | ... | ... | ... | {len(findings) - 300} more findings omitted |")

    if skipped:
        print()
        print("## Skipped")
        print()
        print("| Entry | Reason |")
        print("| -- | -- |")
        for entry, reason in skipped[:200]:
            print(f"| `{md_cell(entry)}` | {md_cell(reason)} |")
        if len(skipped) > 200:
            print(f"| ... | {len(skipped) - 200} more skipped entries omitted |")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Static scanner for pre-install skill security audits.")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown")
    parser.add_argument("--include-vendor", action="store_true", help="Include vendor/cache directories such as node_modules")
    parser.add_argument("--max-bytes", type=int, default=1_000_000, help="Maximum bytes to read per file")
    args = parser.parse_args(argv)

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"Target does not exist: {target}", file=sys.stderr)
        return 2

    root = target if target.is_dir() else target.parent
    regexes = [(level, category, re.compile(pattern, re.IGNORECASE), label) for level, category, pattern, label in PATTERNS]
    files, skipped = collect_files(target, args.include_vendor)

    findings: list[Finding] = []
    for file_path in files:
        file_findings, skip_reason = scan_file(file_path, root, args.max_bytes, regexes)
        findings.extend(file_findings)
        if skip_reason:
            skipped.append((rel(file_path, root), skip_reason))

    if args.json:
        payload = {
            "target": str(target),
            "files_discovered": len(files),
            "skipped": [{"entry": entry, "reason": reason} for entry, reason in skipped],
            "findings": [asdict(finding) for finding in findings],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_markdown(target, files, skipped, findings, root)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
