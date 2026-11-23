# Skill Security Auditor

Static pre-install security audit skill for Codex.

This skill helps review external Codex skills, plugins, agents, prompt packs, scripts, archives, and repositories before installation. It focuses on prompt-injection risk, malicious code, dependency/install hooks, network behavior, sensitive data access, persistence, auto-execution, and permission overreach.

## 中文简介

在安装第三方 Codex 技能、插件或脚本之前，用它检查提示指令、依赖安装行为、联网请求、敏感数据访问和权限范围。审查通过阅读文件与配置完成，扫描器把可疑位置列为人工核查线索，最终报告给出风险等级、依据和安装建议。

把项目复制到 `~/.codex/skills/skill-security-auditor` 后，在新的 Codex 对话中使用 `$skill-security-auditor`，并提供要审查的目录。

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
