"""CLI entry point — mcp-audit scan."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .auditor import MCPAuditor
from .reporter import generate_text_report, generate_json_report


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mcp-audit",
        description="Scan any MCP server for security issues",
    )
    sub = parser.add_subparsers(dest="command")

    # scan — text report
    scan_p = sub.add_parser("scan", help="Audit an MCP server (text report)")
    scan_p.add_argument("--server", "-s", required=True, help="Server command (e.g. 'python -m my_server')")
    scan_p.add_argument("--threshold", "-t", default="LOW", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        help="Injection detection threshold (default: LOW)")
    scan_p.add_argument("--live-tests", action="store_true",
                        help="Run live injection tests (may cause side effects!)")

    # scan-json — JSON report
    json_p = sub.add_parser("scan-json", help="Audit an MCP server (JSON report)")
    json_p.add_argument("--server", "-s", required=True, help="Server command")
    json_p.add_argument("--threshold", "-t", default="LOW", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    json_p.add_argument("--live-tests", action="store_true")
    json_p.add_argument("--output", "-o", help="Output file (default: stdout)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    auditor = MCPAuditor(
        server_command=args.server,
        injection_threshold=args.threshold,
        run_live_tests=args.live_tests,
    )

    if args.live_tests:
        print("WARNING: Live injection tests enabled. This sends payloads to the server.", file=sys.stderr)
        print("         Only use on servers you own or have permission to test.", file=sys.stderr)
        print("", file=sys.stderr)

    result = asyncio.run(auditor.run())

    if args.command == "scan":
        print(generate_text_report(result))
    elif args.command == "scan-json":
        report = generate_json_report(result)
        output = json.dumps(report, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Report saved to {args.output}", file=sys.stderr)
        else:
            print(output)

    # Exit code: 0 for A/B, 1 for C/D/F (CI/CD friendly)
    sys.exit(0 if result.grade in ("A", "B") else 1)


if __name__ == "__main__":
    main()
