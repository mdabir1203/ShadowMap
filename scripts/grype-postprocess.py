#!/usr/bin/env python3
"""Post-process Grype reports to enforce fail-on levels and optional reachability checks."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

SEVERITY_ORDER = {
    "unknown": -1,
    "negligible": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SKIP_DIRS = {".git", "target", "node_modules", "vendor", "dist", "build"}
TEXT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".json",
    ".kt",
    ".m",
    ".md",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".swift",
    ".ts",
    ".tsx",
    ".vue",
    ".yaml",
    ".yml",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, help="Path to the Grype JSON report")
    parser.add_argument(
        "--fail-on",
        default="medium",
        help="Lowest severity that should fail the scan (default: medium)",
    )
    parser.add_argument(
        "--enable-reachability-analysis",
        action="store_true",
        help="Enable reachability analysis using vulnerable function metadata",
    )
    parser.add_argument(
        "--source-root",
        default=None,
        help="Root directory for reachability analysis (defaults to the repo root)",
    )
    parser.add_argument(
        "--function-map",
        default=None,
        help=(
            "Optional JSON file mapping CVE IDs to vulnerable function names to augment "
            "metadata discovered in the Grype report."
        ),
    )
    return parser.parse_args()


def severity_threshold(level: str) -> int:
    normalized = level.strip().lower()
    if normalized not in SEVERITY_ORDER:
        raise ValueError(f"Unknown severity level '{level}'. Valid options: {', '.join(SEVERITY_ORDER)}")
    return SEVERITY_ORDER[normalized]


def load_report(path: Path) -> Dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_report(path: Path, data: Dict) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")


def load_function_map(path: Optional[Path]) -> Dict[str, List[str]]:
    if not path:
        return {}
    with path.open("r", encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Failed to parse function map '{path}': {exc}") from exc
    mapping: Dict[str, List[str]] = {}
    for key, value in data.items():
        if isinstance(value, str):
            mapping[key] = [value]
        elif isinstance(value, Iterable):
            mapping[key] = [str(item) for item in value if isinstance(item, (str, int, float))]
        else:
            raise SystemExit(f"Function map entries must be strings or arrays of strings (got {type(value)!r})")
    return mapping


def discover_functions(match: Dict, mapping: Dict[str, List[str]]) -> List[str]:
    vuln = match.get("vulnerability", {})
    metadata = vuln.get("metadata", {})
    functions: Set[str] = set()

    if isinstance(metadata, dict):
        for key in ("vulnerableFunctions", "vulnerable_functions", "vulnerable-functions"):
            value = metadata.get(key)
            if isinstance(value, str):
                functions.add(value)
            elif isinstance(value, Iterable):
                for item in value:
                    if isinstance(item, str):
                        functions.add(item)

    vuln_id = vuln.get("id")
    if vuln_id and vuln_id in mapping:
        functions.update(mapping[vuln_id])

    return sorted(functions)


def scan_for_function_calls(root: Path, function: str) -> List[Tuple[Path, int, str]]:
    pattern = re.compile(rf'\b{re.escape(function)}\s*\(')
    matches: List[Tuple[Path, int, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            path = Path(dirpath, filename)
            if path.suffix and path.suffix.lower() not in TEXT_EXTENSIONS:
                continue
            try:
                with path.open("r", encoding="utf-8", errors="ignore") as handle:
                    for lineno, line in enumerate(handle, 1):
                        if pattern.search(line):
                            snippet = line.strip()
                            matches.append((path, lineno, snippet))
            except OSError:
                continue
    return matches


def annotate_reachability(
    data: Dict,
    source_root: Path,
    mapping: Dict[str, List[str]],
) -> Dict[str, Dict[str, object]]:
    reachability: Dict[str, Dict[str, object]] = {}
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        vuln_id = vuln.get("id", "unknown")
        functions = discover_functions(match, mapping)
        status = "unknown"
        evidence: List[Dict[str, object]] = []
        if functions:
            for func in functions:
                call_sites = scan_for_function_calls(source_root, func)
                if call_sites:
                    status = "reachable"
                    evidence.extend(
                        {
                            "function": func,
                            "file": str(path.relative_to(source_root)),
                            "line": line_no,
                            "code": snippet,
                        }
                        for path, line_no, snippet in call_sites
                    )
                else:
                    evidence.append({"function": func, "reachable": False})
            if status != "reachable":
                status = "unreachable"
        reachability[vuln_id] = {"status": status, "evidence": evidence}
        match["reachability"] = reachability[vuln_id]
    return reachability


def main() -> int:
    args = parse_args()

    report_path = Path(args.report)
    data = load_report(report_path)
    fail_threshold = severity_threshold(args.fail_on)

    function_map_path = Path(args.function_map) if args.function_map else None
    function_map = load_function_map(function_map_path)

    source_root = Path(args.source_root) if args.source_root else Path.cwd()

    reachability_cache: Dict[str, Dict[str, object]] = {}
    if args.enable_reachability_analysis:
        if not source_root.exists():
            raise SystemExit(f"Source root '{source_root}' does not exist")
        reachability_cache = annotate_reachability(data, source_root, function_map)

    failed_vulns: List[str] = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        severity = vuln.get("severity", "unknown").lower()
        severity_rank = SEVERITY_ORDER.get(severity, -1)
        reachability_status = match.get("reachability", {}).get("status", "unknown")
        if severity_rank >= fail_threshold:
            if reachability_status == "unreachable":
                continue
            failed_vulns.append(vuln.get("id", "unknown"))

    write_report(report_path, data)

    if failed_vulns:
        print(
            "Security scan failed: vulnerabilities meeting or exceeding the fail-on severity "
            f"('{args.fail_on}') remain reachable:",
            file=sys.stderr,
        )
        for vuln_id in failed_vulns:
            status = reachability_cache.get(vuln_id, {"status": "unknown"})
            print(f"  - {vuln_id} (reachability: {status.get('status', 'unknown')})", file=sys.stderr)
        return 1

    print(
        "Security scan passed: no reachable vulnerabilities meet or exceed the fail-on severity "
        f"('{args.fail_on}')."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
