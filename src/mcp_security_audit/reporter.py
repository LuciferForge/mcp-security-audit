"""Report generation — text and JSON output from audit results."""

from __future__ import annotations

from typing import Any

from .auditor import AuditResult, Severity
from .classifier import CATEGORY_LABELS


def generate_text_report(result: AuditResult) -> str:
    """Generate a human-readable text report."""
    lines: list[str] = []
    w = lines.append

    w("=" * 60)
    w("  MCP SECURITY AUDIT REPORT")
    w("=" * 60)
    w("")
    w(f"  Server:  {result.server_command}")
    w(f"  Tools:   {result.tool_count}")
    w(f"  Score:   {result.score}/100  (Grade {result.grade})")
    w("")

    if result.error:
        w(f"  ERROR: {result.error}")
        w("")
        return "\n".join(lines)

    # Tool classification table
    w("-" * 60)
    w("  TOOL CLASSIFICATION")
    w("-" * 60)
    w(f"  {'Tool':<30} {'Risk':<10} {'Matched'}")
    w(f"  {'-'*29} {'-'*9} {'-'*18}")
    for c in result.classifications:
        matched = ", ".join(c.matched_patterns[:3]) if c.matched_patterns else "-"
        risk_marker = "!!" if c.is_high_risk else "  "
        w(f"  {c.tool_name:<30} {c.label:<10} {risk_marker}{matched}")
    w("")

    # Findings
    if result.findings:
        w("-" * 60)
        w("  FINDINGS")
        w("-" * 60)
        for i, f in enumerate(result.findings, 1):
            icon = _severity_icon(f.severity)
            w(f"  {icon} [{f.severity.value}] {f.title}")
            w(f"     {f.detail}")
            w("")
    else:
        w("  No findings — server looks clean.")
        w("")

    # Live test results
    if result.live_test_results:
        w("-" * 60)
        w("  LIVE INJECTION TESTS")
        w("-" * 60)
        flagged = [t for t in result.live_test_results if t["response_flagged"]]
        w(f"  Tests run:    {len(result.live_test_results)}")
        w(f"  Flagged:      {len(flagged)}")
        if flagged:
            for t in flagged:
                w(f"  !! {t['tool']}:{t['param']} — payload triggered suspicious response")
        w("")

    # Summary
    w("-" * 60)
    severity_counts = {}
    for f in result.findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
    w(f"  Summary: {len(result.findings)} finding(s)")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = severity_counts.get(sev, 0)
        if count:
            w(f"    {sev}: {count}")
    w(f"  Score: {result.score}/100  Grade: {result.grade}")
    w("=" * 60)

    return "\n".join(lines)


def generate_json_report(result: AuditResult) -> dict[str, Any]:
    """Generate a structured JSON-compatible report."""
    return {
        "server": result.server_command,
        "score": result.score,
        "grade": result.grade,
        "error": result.error or None,
        "summary": {
            "tool_count": result.tool_count,
            "resource_count": len(result.resources),
            "prompt_count": len(result.prompts),
            "finding_count": len(result.findings),
            "high_risk_tools": len(result.high_risk_tools),
        },
        "tools": [
            {
                "name": c.tool_name,
                "category": c.label,
                "is_high_risk": c.is_high_risk,
                "matched_patterns": c.matched_patterns,
                "confidence": c.confidence,
            }
            for c in result.classifications
        ],
        "findings": [
            {
                "severity": f.severity.value,
                "category": f.category,
                "title": f.title,
                "detail": f.detail,
                "tool_name": f.tool_name or None,
            }
            for f in result.findings
        ],
        "resources": result.resources,
        "prompts": result.prompts,
        "live_tests": result.live_test_results if result.live_test_results else None,
    }


def _severity_icon(severity: Severity) -> str:
    if severity == Severity.CRITICAL:
        return "XX"
    elif severity == Severity.HIGH:
        return "!!"
    elif severity == Severity.MEDIUM:
        return "--"
    elif severity == Severity.LOW:
        return ".."
    return "  "
