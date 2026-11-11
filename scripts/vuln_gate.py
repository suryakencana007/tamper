#!/usr/bin/env python3
"""The vulnerability gate: parse govulncheck's output and decide.

WHY THIS IS A SCRIPT WITH A TEST, and not an inline heredoc.

The version of this gate that lived inside ci.yml had been GREEN for every run since it was
written, while govulncheck reported findings. The reason is one line: it did

    for line in fh: obj = json.loads(line)

and `govulncheck -json` does NOT emit JSON-lines. It emits a stream of pretty-printed JSON
objects, one after another, each spanning many lines. So every single line failed to parse, every
failure was `continue`d as "mixed message kinds", `found` stayed empty, and the step passed.

That is the defect this repository spent a whole roadmap removing — a check that cannot fail — in
the one place where it costs the most.

So the parser is a file, and `vuln_gate_test.go` feeds it fixtures: one with a finding (must exit
non-zero), one with the pinned allow-listed advisory (must pass), one with no config message (must
fail), one with a stale database (must fail). A gate that has never failed is not known to work.

Exit codes: 0 = clean or allow-listed only; 1 = findings; 2 = the report itself is unusable.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone

# The only advisory this repository tolerates in its own code, and the reason travels with it.
#
# GO-2026-6909: crewjam/saml through v0.5.1 — nil <Issuer> deref and namespace-blind NameID. FIXED
# UPSTREAM in v0.5.2/v0.6.3; tamper is on v0.6.3 and the behaviour change is proven by probe
# (docs/phases/PHASE17-...: a foreign-namespace AttributeValue landed under v0.5.1 and does not
# under v0.6.3). The advisory still reports "Fixed in: NONE", so every scanner flags every version
# until the metadata is corrected — crewjam/saml#693. When that lands, delete this entry.
ALLOW = {"GO-2026-6909"}

# A database older than this is treated as a broken scan rather than as a clean bill of health:
# a scanner reading a stale snapshot is indistinguishable from one reporting nothing.
MAX_DB_AGE = timedelta(days=30)

# Findings reachable from this module block a release. Everything else is reported.
OUR_MODULE = "github.com/suryakencana007/tamper"


def parse_stream(text: str) -> list[dict]:
    """Parse govulncheck's stream of concatenated (possibly pretty-printed) JSON objects."""
    decoder = json.JSONDecoder()
    objects, i = [], 0
    while True:
        while i < len(text) and text[i] in " \t\r\n":
            i += 1
        if i >= len(text):
            return objects
        obj, i = decoder.raw_decode(text, i)
        objects.append(obj)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: vuln_gate.py <govulncheck.json>", file=sys.stderr)
        return 2
    text = open(argv[1], encoding="utf-8", errors="replace").read()
    try:
        objects = parse_stream(text)
    except json.JSONDecodeError as err:
        print(f"the scan report is not parseable ({err}) — treating as failure, not as clean", file=sys.stderr)
        return 2

    config = next((o["config"] for o in objects if isinstance(o.get("config"), dict)), None)
    if config is None:
        print("no config message in the report — the scanner did not describe what it scanned; "
              "treating as failure, not as clean", file=sys.stderr)
        return 2
    if not any("SBOM" in o for o in objects):
        print("no SBOM in the report — the scan did not enumerate modules; treating as failure",
              file=sys.stderr)
        return 2

    stamp = config.get("db_last_modified", "")
    try:
        db_at = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        print(f"unreadable db_last_modified {stamp!r} — treating as failure", file=sys.stderr)
        return 2
    age = datetime.now(timezone.utc) - db_at
    if age > MAX_DB_AGE:
        print(f"the vulnerability database is {age.days} days old ({stamp}) — a stale database reads "
              f"exactly like a clean scan, so this is a failure", file=sys.stderr)
        return 2

    found, allowed = set(), set()
    for obj in objects:
        finding = obj.get("finding")
        if not isinstance(finding, dict):
            continue
        osv = finding.get("osv", "")
        if not isinstance(osv, str) or not osv:
            continue
        # Reachability, not mere presence. govulncheck's value is the call graph: a finding whose
        # trace contains no frame from THIS module is an advisory in a dependency we import but do
        # not reach, and blocking on those would make the gate noisy enough to be bypassed. The test
        # for it is the trace's module field, not the length of the trace — a vulnerable symbol in a
        # dependency also carries a trace, just not through our code.
        reachable = any(
            (frame.get("module") or "") == OUR_MODULE
            for frame in (finding.get("trace") or [])
            if isinstance(frame, dict)
        )
        (found if (reachable and osv not in ALLOW) else allowed).add(osv)

    print(f"govulncheck: go {config.get('go_version')}, db {stamp}, "
          f"{len(objects)} report objects")
    if found:
        print("vulnerabilities in code: " + ", ".join(sorted(found)), file=sys.stderr)
        return 1
    if allowed:
        print("allow-listed (see the comment in scripts/vuln_gate.py): " + ", ".join(sorted(allowed)))
    print("no vulnerabilities in called code")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
