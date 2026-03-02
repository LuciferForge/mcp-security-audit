"""MCP server mode — expose audit tools via MCP protocol."""

from __future__ import annotations

import asyncio

from mcp.server.fastmcp import FastMCP
from prompt_shield import PromptScanner

from .auditor import MCPAuditor
from .classifier import classify_tool, CATEGORY_LABELS
from .reporter import generate_text_report, generate_json_report

mcp = FastMCP(
    "MCP Security Auditor",
    instructions=(
        "Security audit tools for MCP servers. Connect to any MCP server, "
        "enumerate its tools/resources/prompts, scan for injection patterns, "
        "classify tool risk levels, and produce a scored security report."
    ),
)


@mcp.tool()
async def audit_scan(
    server_command: str,
    live_tests: bool = False,
    threshold: str = "LOW",
) -> str:
    """Run a full security audit on an MCP server.

    Connects to the target server, enumerates all tools/resources/prompts,
    classifies risk levels, scans for injection patterns, and produces a
    scored report (0-100, grades A-F).

    Args:
        server_command: Command to start the MCP server (e.g. "python -m my_server").
        live_tests: If true, sends injection payloads to test tools (use with caution).
        threshold: Injection detection sensitivity — "LOW", "MEDIUM", "HIGH", "CRITICAL".
    """
    auditor = MCPAuditor(
        server_command=server_command,
        injection_threshold=threshold,
        run_live_tests=live_tests,
    )
    result = await auditor.run()
    return generate_text_report(result)


@mcp.tool()
async def audit_quick_scan(server_command: str) -> dict:
    """Quick security scan — returns score, grade, and top findings only.

    Args:
        server_command: Command to start the MCP server.
    """
    auditor = MCPAuditor(server_command=server_command, run_live_tests=False)
    result = await auditor.run()
    report = generate_json_report(result)
    return {
        "score": report["score"],
        "grade": report["grade"],
        "tool_count": report["summary"]["tool_count"],
        "high_risk_tools": report["summary"]["high_risk_tools"],
        "finding_count": report["summary"]["finding_count"],
        "top_findings": [
            {"severity": f["severity"], "title": f["title"]}
            for f in report["findings"][:5]
        ],
    }


@mcp.tool()
def audit_classify(tool_name: str, tool_description: str = "") -> dict:
    """Classify a single tool's risk level without connecting to a server.

    Args:
        tool_name: The tool's name (e.g. "execute_command", "read_file").
        tool_description: The tool's description text.
    """
    c = classify_tool(tool_name, tool_description)
    return {
        "tool_name": c.tool_name,
        "category": c.label,
        "is_high_risk": c.is_high_risk,
        "matched_patterns": c.matched_patterns,
        "confidence": c.confidence,
    }


@mcp.tool()
def audit_check_text(text: str, threshold: str = "LOW") -> dict:
    """Scan arbitrary text for prompt injection patterns.

    Args:
        text: Text to scan for injection patterns.
        threshold: Detection sensitivity — "LOW", "MEDIUM", "HIGH", "CRITICAL".
    """
    scanner = PromptScanner(threshold=threshold)
    result = scanner.scan(text)
    return {
        "is_safe": result.is_safe,
        "severity": result.severity,
        "risk_score": result.risk_score,
        "matches": [{"name": m["name"], "category": m["category"]} for m in result.matches],
    }


def main():
    """Run the MCP server (stdio transport)."""
    mcp.run()


if __name__ == "__main__":
    main()
