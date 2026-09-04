from __future__ import annotations

import argparse
import json
from typing import Sequence

from .scanner import scan_path


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="configflare", description="Audit MCP and coding-agent configuration")
    result.add_argument("path", nargs="?", default=".")
    result.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    result.add_argument("--fail-on", choices=("never", "low", "medium", "high", "critical"), default="high")
    return result


def format_text(report) -> str:
    lines = [f"ConfigFlare risk: {report.score}/100 ({report.level})", f"{report.files_scanned} configs · {report.servers_scanned} servers · {len(report.findings)} findings"]
    lines.extend(f"- [{item.severity}] {item.path} {item.location}: {item.message} ({item.fingerprint})" for item in report.findings)
    return "\n".join(lines)


def format_markdown(report) -> str:
    rows = "\n".join(f"| {item.severity} | `{item.path}` | `{item.location}` | {item.message} |" for item in report.findings) or "| — | — | — | No findings |"
    return f"## ConfigFlare report\n\n**Risk: {report.score}/100 ({report.level})**\n\n| Severity | File | Location | Finding |\n|---|---|---|---|\n{rows}"


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    report = scan_path(args.path)
    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    elif args.format == "markdown":
        print(format_markdown(report))
    else:
        print(format_text(report))
    levels = {"low": 1, "medium": 2, "high": 3, "critical": 4, "never": 99}
    return 2 if levels[report.level] >= levels[args.fail_on] else 0


if __name__ == "__main__":
    raise SystemExit(main())
