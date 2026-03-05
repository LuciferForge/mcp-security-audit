"""Report generation — text and JSON output from audit results."""

from __future__ import annotations

from typing import Any

from .auditor import AuditResult, Severity
from .classifier import CATEGORY_LABELS, is_purpose_aligned


def generate_text_report(result: AuditResult) -> str:
    """Generate a human-readable text report with dual output:
    risk profile (label) + hygiene score (0-100 breakdown)."""
    lines: list[str] = []
    w = lines.append

    w("=" * 60)
    w("  MCP SECURITY AUDIT REPORT")
    w("=" * 60)
    w("")
    server_label = result.server_name or result.server_command
    if result.server_version:
        server_label += f" v{result.server_version}"
    w(f"  Server:       {server_label}")
    w(f"  Tools:        {result.tool_count}")
    w(f"  Risk Profile: {result.risk_profile}")
    if result.server_purpose:
        purpose_labels = sorted(
            CATEGORY_LABELS.get(p, str(p)) for p in result.server_purpose
        )
        w(f"  Purpose:      {', '.join(purpose_labels)}")
    w(f"  Hygiene:      {result.score}/100  (Grade {result.grade})")
    w("")

    if result.error:
        w(f"  ERROR: {result.error}")
        w("")
        return "\n".join(lines)

    # Hygiene score breakdown
    h = result.hygiene
    w("-" * 60)
    w("  HYGIENE SCORE BREAKDOWN")
    w("-" * 60)
    w(f"  {'Category':<28} {'Score':>6}  {'Max':>4}")
    w(f"  {'-'*27} {'-'*6}  {'-'*4}")
    w(f"  {'Documentation':<28} {h.documentation:>5.1f}  {'/25':>4}")
    w(f"  {'Schema Rigor':<28} {h.schema_rigor:>5.1f}  {'/25':>4}")
    w(f"  {'Injection Safety':<28} {h.injection_safety:>5.1f}  {'/25':>4}")
    w(f"  {'Scope & Least Privilege':<28} {h.scope_signals:>5.1f}  {'/15':>4}")
    w(f"  {'Metadata':<28} {h.metadata:>5.1f}  {'/10':>4}")
    w(f"  {'-'*27} {'-'*6}  {'-'*4}")
    w(f"  {'TOTAL':<28} {h.total:>5d}  /100")
    w("")

    # Tool classification table
    w("-" * 60)
    w("  TOOL CLASSIFICATION")
    w("-" * 60)
    w(f"  {'Tool':<30} {'Risk':<10} {'Matched'}")
    w(f"  {'-'*29} {'-'*9} {'-'*18}")
    for c in result.classifications:
        matched = ", ".join(c.matched_patterns[:3]) if c.matched_patterns else "-"
        aligned = is_purpose_aligned(c, result.server_purpose)
        if c.is_high_risk and not aligned:
            risk_marker = "!!"  # Unexpected capability — flag it
        elif c.is_high_risk and aligned:
            risk_marker = "ok"  # Expected capability — no alarm
        else:
            risk_marker = "  "
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
    severity_counts: dict[str, int] = {}
    for f in result.findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
    w(f"  Risk Profile: {result.risk_profile}  |  Hygiene: {result.score}/100 Grade {result.grade}")
    if result.findings:
        w(f"  Findings: {len(result.findings)}", )
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = severity_counts.get(sev, 0)
            if count:
                w(f"    {sev}: {count}")
    else:
        w("  Findings: 0")
    w("=" * 60)

    return "\n".join(lines)


def generate_json_report(result: AuditResult) -> dict[str, Any]:
    """Generate a structured JSON-compatible report."""
    purpose_labels = sorted(
        CATEGORY_LABELS.get(p, str(p)) for p in result.server_purpose
    ) if result.server_purpose else []
    return {
        "server": result.server_command,
        "server_name": result.server_name or None,
        "server_version": result.server_version or None,
        "risk_profile": result.risk_profile,
        "server_purpose": purpose_labels,
        "purpose_aligned": result.purpose_aligned,
        "hygiene_score": result.score,
        "grade": result.grade,
        "hygiene_breakdown": {
            "documentation": round(result.hygiene.documentation, 1),
            "schema_rigor": round(result.hygiene.schema_rigor, 1),
            "injection_safety": round(result.hygiene.injection_safety, 1),
            "scope_signals": round(result.hygiene.scope_signals, 1),
            "metadata": round(result.hygiene.metadata, 1),
        },
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
                "purpose_aligned": is_purpose_aligned(c, result.server_purpose),
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
