#!/usr/bin/env python3
"""Evidence runner/checker for the CedarScan finding validation.

Run from the candidate/ directory (stdlib only, Python 3.10+, offline):

    python3 evidence/check.py             # run + assert; exit 0 only if everything holds
    python3 evidence/check.py --capture   # re-record evidence/captured/*.json (after reviewing a change)
    python3 evidence/check.py --selftest  # prove the checker FAILS when app behaviour changes

What it does: replays request files through the ORIGINAL CLI (inputs/lab.py, unmodified),
then asserts status, exact body, header values and header absence for every request,
compares output to the captured baseline (drift detection), and verifies lab.py's hash.
"""
import argparse, hashlib, importlib.util, json, pathlib, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
EV = ROOT / "evidence"
LAB = ROOT / "inputs" / "lab.py"
REQ_FILES = [ROOT / "inputs" / "requests.json", EV / "requests_evidence.json"]
ALLOWED_KEYS = {"request_id", "route", "session", "report_id", "query"}  # per contract.md


def load_json(p):
    return json.loads(pathlib.Path(p).read_text(encoding="utf-8"))


def run_cli(lab, req_file):
    p = subprocess.run([sys.executable, str(lab), str(req_file)], capture_output=True, text=True, timeout=30)
    if p.returncode != 0:
        raise RuntimeError(f"lab.py failed on {req_file}: {p.stderr.strip()[-300:]}")
    return json.loads(p.stdout)


def check_one(resp, exp):
    f = []
    if resp["status"] != exp["status"]:
        f.append(f"status {resp['status']} != expected {exp['status']}")
    if resp["body"] != exp["body"]:
        f.append(f"body {resp['body']!r} != expected {exp['body']!r}")
    for k, v in exp.get("headers", {}).items():
        if resp["headers"].get(k) != v:
            f.append(f"header {k}={resp['headers'].get(k)!r} != expected {v!r}")
    for k in exp.get("headers_absent", []):
        if k in resp["headers"]:
            f.append(f"header {k} unexpectedly present: {resp['headers'][k]!r}")
    return f


def evaluate(lab, verbose=False, capture=False):
    """Return (failures: {request_id or '<meta>': [msgs]}, outputs: {filename: data})."""
    expect = load_json(EV / "expectations.json")
    failures, outputs, seen = {}, {}, set()
    def bad(rid, msg): failures.setdefault(rid, []).append(msg)
    for rf in REQ_FILES:
        reqs = load_json(rf)
        for r in reqs:
            extra = set(r) - ALLOWED_KEYS
            if extra: bad(r["request_id"], f"request has keys outside contract: {sorted(extra)}")
            if r["request_id"] in seen: bad(r["request_id"], "duplicate request_id")
            seen.add(r["request_id"])
        out = run_cli(lab, rf)
        outputs[rf.stem + "_output.json"] = out
        by_id = {o["request_id"]: o for o in out}
        for r in reqs:
            rid = r["request_id"]
            if rid not in expect: bad(rid, "no expectation defined (every request must be asserted)"); continue
            if rid not in by_id: bad(rid, "no response"); continue
            msgs = check_one(by_id[rid], expect[rid])
            for m in msgs: bad(rid, m)
            if verbose:
                e = expect[rid]
                print(f"{'FAIL' if msgs else 'PASS'}  {rid:32} [{e['finding']:4}] {e['kind']:11} -> {by_id[rid]['status']} {by_id[rid]['body']!r}")
    for rid in set(expect) - seen:
        bad(rid, "expectation has no matching request")
    return failures, outputs


def malformed(lab, verbose=False):
    spec = importlib.util.spec_from_file_location("lab_under_test", lab)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    exp = load_json(EV / "expectations_malformed.json")
    fails = {}
    for r in load_json(EV / "requests_malformed.json"):
        want = exp[r["request_id"]]["exception"]
        try:
            res = mod.respond(r); got = f"no exception (status {res['status']})"
        except Exception as e:  # noqa: BLE001
            got = type(e).__name__
        ok = got == want
        if not ok: fails[r["request_id"]] = [f"raised {got}, expected {want}"]
        if verbose: print(f"{'PASS' if ok else 'FAIL'}  {r['request_id']:32} [out-of-contract] raises {got}")
    return fails


MUTANTS = {  # (description, old, new, request_ids that MUST fail)
    "fix-f01-add-tenant-check": ('elif report is None:', 'elif report is None or report["tenant"] != tenant:', {"f01-red-reads-blue", "f01-blue-reads-red"}),
    "break-escaping": ('html.escape(request.get("query", ""), quote=True)', 'request.get("query", "")', {"f02-script-tag", "f02-attr-breakout", "f02-img-onerror", "f02-entity-passthrough"}),
    "open-anonymous-access": ('if tenant is None:', 'if False:', {"f03-no-session-red", "f03-no-session-blue", "f03-unknown-session", "f03-empty-session", "f03-case-variant-session"}),
    "add-csp-header": ('"X-Frame-Options": "DENY"}', '"X-Frame-Options": "DENY", "Content-Security-Policy": "default-src \'none\'"}', {"f04-preview-headers"}),
}


def selftest():
    src = LAB.read_text(encoding="utf-8")
    ok_all = True
    for name, (old, new, must_fail) in MUTANTS.items():
        assert src.count(old) == 1, f"mutation anchor not unique/absent: {old}"
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "lab.py"; p.write_text(src.replace(old, new), encoding="utf-8")
            fails, _ = evaluate(p)
        missing = must_fail - set(fails)
        ok = not missing
        ok_all &= ok
        print(f"{'OK  ' if ok else 'MISS'} mutant {name}: checker failed on {sorted(fails)}" + (f"  (did NOT catch: {sorted(missing)})" if missing else ""))
    print("SELFTEST", "PASSED: checker detects every injected behaviour change" if ok_all else "FAILED")
    return 0 if ok_all else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", action="store_true"); ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest: sys.exit(selftest())
    print(f"python {sys.version.split()[0]}  lab={LAB.relative_to(ROOT)}")
    failures, outputs = {}, None
    def merge(d):
        for k, v in d.items(): failures.setdefault(k, []).extend(v)
    if hashlib.sha256(LAB.read_bytes()).hexdigest() != (EV / "lab.py.sha256").read_text().strip():
        merge({"<meta>": ["inputs/lab.py differs from the original supplied file (hash mismatch)"]})
    f, outputs = evaluate(LAB, verbose=True); merge(f)
    merge(malformed(LAB, verbose=True))
    cap = EV / "captured"
    for name, data in outputs.items():
        if a.capture:
            (cap / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        elif not (cap / name).exists() or load_json(cap / name) != data:
            merge({"<meta>": [f"live output differs from captured/{name} (behaviour drift)"]})
    if failures:
        print("\nFAILED:")
        for k, v in failures.items():
            for m in v: print(f"  - {k}: {m}")
        sys.exit(1)
    print(f"\nALL CHECKS PASSED{' (captured outputs rewritten)' if a.capture else ''}")


if __name__ == "__main__":
    main()
