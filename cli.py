#!/usr/bin/env python3
"""
SecureLens CLI — scan files or folders from the terminal or in CI.

    python cli.py examples/vulnerable_app.py
    python cli.py src/ --ai --fail-on high
    python cli.py app/ --json > report.json

Exit code is 1 when any finding is at or above --fail-on, so it can gate a pipeline.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app import ai
from app.scanner import EXTENSION_LANG, SEVERITY_ORDER, scan

COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[37m"}
RESET = "\033[0m"
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "tests"}


def collect(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.suffix in EXTENSION_LANG and not (set(f.parts) & SKIP_DIRS):
                    files.append(f)
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description="SecureLens security scanner")
    parser.add_argument("paths", nargs="+", help="files or directories to scan")
    parser.add_argument("--ai", action="store_true", help="enable Claude review (needs ANTHROPIC_API_KEY)")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="high",
                        help="exit 1 if a finding at or above this severity exists (default: high)")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    files = collect(args.paths)
    if not files:
        print("No supported source files found.", file=sys.stderr)
        return 2

    threshold = SEVERITY_ORDER[args.fail_on]
    report, failed = [], False
    for f in files:
        code = f.read_text(encoding="utf-8", errors="replace")
        result = scan(code, filename=f.name)
        review = ai.review(code, result) if args.ai else ai._offline_review(result, "static-only")
        payload = ai.merge(result, review)
        payload["file"] = str(f)
        report.append(payload)
        failed |= any(SEVERITY_ORDER[x["severity"]] >= threshold
                      for x in payload["findings"] if not x["false_positive"])

    if args.json:
        print(json.dumps(report, indent=2))
        return 1 if failed else 0

    color = (lambda s, c: s) if args.no_color or not sys.stdout.isatty() else (lambda s, c: f"{COLORS[c]}{s}{RESET}")
    total = 0
    for r in report:
        active = [x for x in r["findings"] if not x["false_positive"]]
        total += len(active)
        print(f"\n{r['file']}  [{r['language']}]  risk {r['risk_score']}/100  ({len(active)} findings)")
        for x in active:
            tag = color(f"{x['severity'].upper():<8}", x["severity"])
            print(f"  {tag} L{x['line']:<4} {x['title']}  ({x['cwe']})")
            if x.get("snippet"):
                print(f"           {x['snippet'][:100]}")
    print(f"\nScanned {len(report)} file(s), {total} finding(s). "
          f"{'FAILED' if failed else 'PASSED'} (fail-on: {args.fail_on})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
