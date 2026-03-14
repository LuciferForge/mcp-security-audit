# mcp-security-audit

[![PyPI version](https://img.shields.io/pypi/v/mcp-security-audit)](https://pypi.org/project/mcp-security-audit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

**Security auditor for MCP servers.** Connects to any MCP server, enumerates its tools/resources/prompts, scans for injection patterns, classifies risk levels, and produces a scored report (0-100, grades A-F).

Works as a CLI tool (`mcp-audit`) or as an MCP server itself (`mcp-security-audit`).

---

## Install

```bash
pip install mcp-security-audit
```

## CLI Usage

### Text report

```bash
mcp-audit scan --server "python -m my_mcp_server"
```

### JSON report

```bash
mcp-audit scan-json --server "python -m my_mcp_server" --output report.json
```

### With live injection tests

```bash
mcp-audit scan --server "python -m my_mcp_server" --live-tests
```

### CI/CD

Exit code 0 for grade A/B, 1 for C/D/F:

```bash
mcp-audit scan --server "uvx some-server" || echo "Security audit failed"
```

---

## MCP Server Mode

Use as an MCP server so AI assistants can audit other servers:

### Claude Code

```bash
claude mcp add mcp-security-audit -- uvx mcp-security-audit
```

### Manual

```json
{
  "mcpServers": {
    "mcp-security-audit": {
      "command": "uvx",
      "args": ["mcp-security-audit"]
    }
  }
}
```

### Tools exposed

| Tool | What it does |
|---|---|
| `audit_scan` | Full security audit with text report |
| `audit_quick_scan` | Quick scan — score, grade, top findings |
| `audit_classify` | Classify a single tool's risk level |
| `audit_check_text` | Scan text for injection patterns |

---

## What It Checks

1. **Tool risk classification** — categorizes every tool as SHELL / FILE / DATABASE / NETWORK / SAFE
2. **Injection pattern scanning** — scans tool and prompt descriptions for 75 injection patterns across 9 categories
3. **Resource URI analysis** — flags sensitive paths (.env, .ssh, credentials, etc.)
4. **High-risk ratio** — warns if >50% of tools are FILE or SHELL level
5. **Undocumented tools** — flags tools missing descriptions
6. **Attack surface** — warns on 20+ tools (large) or 50+ (very large)
7. **Live injection tests** (opt-in) — sends payloads to string-parameter tools

## Scoring

Starts at 100, deducts per finding:

| Severity | Deduction |
|---|---|
| CRITICAL | -25 |
| HIGH | -15 |
| MEDIUM | -8 |
| LOW | -3 |

Bonus: +1 per documented tool (max +5).

Grades: A (90+), B (75+), C (60+), D (40+), F (<40)

---

## Example Output

```
============================================================
  MCP SECURITY AUDIT REPORT
============================================================

  Server:  python -m agent_safety_mcp.server
  Tools:   13
  Score:   92/100  (Grade A)

------------------------------------------------------------
  TOOL CLASSIFICATION
------------------------------------------------------------
  Tool                           Risk       Matched
  cost_guard_configure           SAFE       -
  cost_guard_status              SAFE       -
  injection_scan                 SAFE       -
  trace_save                     FILE       !!save, file
  ...
```

---

## Dependencies

- [mcp](https://pypi.org/project/mcp/) — MCP protocol SDK
- [ai-injection-guard](https://pypi.org/project/ai-injection-guard/) — 75 prompt injection detection patterns across 9 categories

Part of the [LuciferForge](https://github.com/LuciferForge) AI Agent Infrastructure Stack.

## License

MIT
