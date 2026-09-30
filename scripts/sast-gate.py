#!/usr/bin/env python3
"""
SAST quality gate (used by .github/workflows/devsecops.yml and by `make sast`).

Why a baseline?
    The inherited Juice Shop code base contains a large number of deliberate
    vulnerabilities that the group did not introduce and is not remediating as
    part of this assignment. Failing on every historical finding would make the
    gate useless, so findings that have been reviewed and accepted are recorded
    in .semgrep/baseline.json. The gate fails only on findings that are NOT in
    the baseline - i.e. on regressions. This is the standard way to introduce
    SAST into a legacy code base.

Usage:
    python3 scripts/sast-gate.py [semgrep-results.json] [baseline.json]
    python3 scripts/sast-gate.py [semgrep-results.json] [baseline.json] --update-baseline

Defaults (what the CI job produces):
    results  = semgrep-raw.json
    baseline = .semgrep/baseline.json
Exit codes:
    0 - no new findings (or baseline updated)
    1 - new findings introduced (the pipeline must fail)
    2 - usage / IO error
"""

import json
import sys
from pathlib import Path


def load(path):
    p = Path(path)
    if not p.exists():
        print(f"::error::file not found: {path}")
        sys.exit(2)
    return json.loads(p.read_text())


def normalise(path):
    """Reduce a path to the same form regardless of where the scan was run.

    Repo-relative ("app/routes/login.ts"), absolute
    ("/home/runner/work/x/app/routes/login.ts") and bare ("routes/login.ts")
    all collapse to "app/routes/login.ts".
    """
    path = path.replace("\\", "/")
    if "/app/" in path:
        path = "app/" + path.split("/app/", 1)[1]
    elif path.startswith("app/"):
        pass
    elif path.startswith(("routes/", "lib/")):
        path = "app/" + path
    return path


def fingerprint(finding):
    """Identify a finding by rule + file, not by line number.

    Keying on the line number would make the gate flap whenever unrelated code
    above the finding moves.
    """
    return f"{finding.get('check_id', '')}|{normalise(finding.get('path', ''))}"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) > 2:
        print(__doc__)
        sys.exit(2)

    results_file = args[0] if len(args) >= 1 else "semgrep-raw.json"
    baseline_path = Path(args[1] if len(args) == 2 else ".semgrep/baseline.json")

    results = load(results_file).get("results", [])

    current = {fingerprint(r): r for r in results}

    if "--update-baseline" in sys.argv:
        out = []
        for key, r in sorted(current.items()):
            check_id, path = key.split("|", 1)
            out.append({
                "check_id": check_id,
                "path": path,
                "severity": r.get("extra", {}).get("severity", "INFO")
            })
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(json.dumps(out, indent=2) + "\n")
        print(f"Recorded {len(out)} accepted finding(s) in {baseline_path}")
        sys.exit(0)

    if not baseline_path.exists():
        print(f"::error::baseline {baseline_path} does not exist. "
              f"Create it with --update-baseline after reviewing the findings.")
        sys.exit(2)

    baseline = {f"{b['check_id']}|{normalise(b['path'])}" for b in load(baseline_path)}
    new = {k: v for k, v in current.items() if k not in baseline}
    fixed = sorted(baseline - set(current))

    print(f"SAST gate: {len(results)} finding(s) in this scan, "
          f"{len(baseline)} accepted in the baseline, {len(new)} new.")

    if fixed:
        print(f"  ({len(fixed)} baseline finding(s) no longer reproduce - "
              f"consider tightening the baseline.)")

    if not new:
        print("SAST gate: PASS - no new findings.")
        sys.exit(0)

    print("\n::error::New SAST findings must be fixed or explicitly accepted:")
    for key, finding in sorted(new.items()):
        rule = finding.get("check_id", "?").split(".")[-1]
        print(f"  [{finding.get('extra', {}).get('severity', '?').upper():8s}] "
              f"{rule:45s} {finding.get('path')}:{finding.get('start', {}).get('line')}")
        print(f"           {finding.get('extra', {}).get('message', '').strip().splitlines()[0] if finding.get('extra', {}).get('message') else ''}")
    sys.exit(1)


if __name__ == "__main__":
    main()
