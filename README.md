# Skill Security Auditor

Static pre-install security audit skill for Codex.

This skill helps review external Codex skills, plugins, agents, prompt packs, scripts, archives, and repositories before installation. It focuses on prompt-injection risk, malicious code, dependency/install hooks, network behavior, sensitive data access, persistence, auto-execution, and permission overreach.

## Safety Model

- Treat every external skill as untrusted until reviewed.
- Use static review only.
- Do not run target code, install target dependencies, trigger target automation, or call target-defined tools.
- Report risks before any installation decision.
- Ask for explicit user confirmation before continuing installation.

## Contents

- `SKILL.md` - Codex skill instructions and report format.
- `references/security-checklist.md` - detailed audit rubric and severity rules.
- `scripts/static_scan.py` - trusted helper script for static text scanning.
- `agents/openai.yaml` - Codex UI metadata.

## Installation

Copy this folder to your Codex skills directory:

```text
~/.codex/skills/skill-security-auditor
```

On Windows:

```text
C:\Users\<you>\.codex\skills\skill-security-auditor
```

Restart Codex or open a new thread, then invoke:

```text
$skill-security-auditor
```

## Static Scanner

The bundled scanner reads files as text and reports suspicious patterns. It does not execute target code, import target modules, install dependencies, or make network requests.

```bash
python scripts/static_scan.py /path/to/target-skill
```

Scanner findings are leads for manual review, not proof that a target is safe or unsafe.

## License

MIT
