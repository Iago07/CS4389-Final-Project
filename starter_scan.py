#!/usr/bin/env python3
"""
starter_scan.py - a tiny, beginner-friendly security scanner.

Usage
-----

$ python starter_scan.py path/to/file_or_folder
[*] Scanning path/to/file_or_folder ...
[*] Dummy check 1: file extension
[*] Dummy check 2: file size
[+] Report written to report.json

This file represents the "framework" part of the project:
- It defines an Orchestrator that runs a set of checks.
- It writes a JSON report that the ML pipeline can later consume.
"""

import argparse
import json
from pathlib import Path
from typing import List, Dict, Any


Finding = Dict[str, Any]


class Orchestrator:
    """
    Super-small scanner engine.

    In a full project, this class would:
    - Call static and dynamic analysis tools.
    - Organize checks into categories M1 to M10.
    - Feed its results to the ML pipeline.

    Here we keep only a few simple example checks as a skeleton.
    """

    def scan(self, target: Path) -> List[Finding]:
        """
        Return a list of findings.

        Each finding is a dict of the form:
            {
                "check": "<name>",
                "category": "<M1..M10 or misc>",
                "result": "<short human readable message>",
                "severity": "<info|low|medium|high>"
            }
        """
        findings: List[Finding] = []

        # Example check 1: file extension (M1 Improper Credential Usage is not
        # really related here, so we keep the category as "framework").
        if target.suffix.lower() == ".apk":
            findings.append(
                {
                    "check": "File extension",
                    "category": "framework",
                    "result": "APK detected",
                    "severity": "info",
                }
            )
        else:
            findings.append(
                {
                    "check": "File extension",
                    "category": "framework",
                    "result": "Not an APK",
                    "severity": "low",
                }
            )

        # Example check 2: file size (large APKs might be more complex)
        size_mb = target.stat().st_size / 1024 / 1024
        if size_mb > 50:
            findings.append(
                {
                    "check": "Oversized file",
                    "category": "framework",
                    "result": f"{size_mb:.1f} MB is large",
                    "severity": "medium",
                }
            )
        else:
            findings.append(
                {
                    "check": "Oversized file",
                    "category": "framework",
                    "result": "Size looks reasonable",
                    "severity": "info",
                }
            )

        # Example placeholder checks for M1 to M10
        # In a real project these would call proper tools or scripts.

        findings.append(
            {
                "check": "M1 Improper Credential Usage",
                "category": "M1",
                "result": "Not implemented - manual check recommended",
                "severity": "info",
            }
        )
        findings.append(
            {
                "check": "M5 Insecure Communication",
                "category": "M5",
                "result": "Not implemented - use intercepting proxy for HTTP(S)",
                "severity": "info",
            }
        )
        findings.append(
            {
                "check": "M9 Insecure Data Storage",
                "category": "M9",
                "result": "Not implemented - review storage and encryption",
                "severity": "info",
            }
        )

        return findings


def parse_cli() -> Path:
    parser = argparse.ArgumentParser(
        description="Starter mobile app security scanner - a learning skeleton."
    )
    parser.add_argument(
        "target",
        type=Path,
        help="File or folder to inspect (must exist)",
    )
    args = parser.parse_args()

    if not args.target.exists():
        parser.error(f"{args.target} does not exist")

    return args.target.resolve()


def main() -> None:
    target = parse_cli()
    print(f"[*] Scanning {target} ...")

    orch = Orchestrator()
    findings = orch.scan(target)

    report_file = Path("report.json")
    with report_file.open("w", encoding="utf-8") as fp:
        json.dump(
            {
                "target": str(target),
                "findings": findings,
            },
            fp,
            indent=2,
        )

    print(f"[+] Report written to {report_file.absolute()}")


if __name__ == "__main__":
    main()
