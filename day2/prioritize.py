#!/usr/bin/env python3
"""Day 2: explainable risk ranking + fix recommendations from a GuardianAI report.

Usage:
  python3 day2/prioritize.py REPORT.json [JUICE_SHOP_SOURCE_DIR] [--out day2/output]

Everything here is rule-based. Fix versions come only from the report (OSV data),
never from an LLM. Reachability is a cheap import check and is labelled as such.
"""
import json, re, sys, os
from collections import defaultdict

args = [a for a in sys.argv[1:] if not a.startswith("--")]
out_dir = "day2/output"
if "--out" in sys.argv:
    out_dir = sys.argv[sys.argv.index("--out") + 1]
    args = [a for a in args if a != out_dir]
report_path = args[0]
src_root = args[1] if len(args) > 1 else None
os.makedirs(out_dir, exist_ok=True)

rep = json.load(open(report_path))
nodes = {n["id"]: n for n in rep["graph"]["nodes"]}

# Packages Juice Shop keeps old on purpose (its own security challenges)
INTENTIONAL = {"jsonwebtoken", "express-jwt", "sanitize-html", "marsdb",
               "crypto-js", "lodash", "notevil", "hbs", "base64url", "jws", "moment"}

def purl_name(p):
    m = re.match(r"pkg:npm/(.+?)@([^#]+)", p or "")
    return (m.group(1).replace("%40", "@"), m.group(2)) if m else (None, None)

def vt(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])

def major(v):
    t = vt(v)
    return t[0] if t else -1

_import_cache = {}
_SRC_FILES = None
_SKIP_DIRS = {"node_modules", "dist", "build", "test", ".git", ".guardian", "coverage"}

def _load_sources():
    """Read app source once (pure Python, so it behaves the same on macOS and Linux)."""
    global _SRC_FILES
    if _SRC_FILES is None:
        _SRC_FILES = []
        for root, dirs, files in os.walk(src_root):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for fn in files:
                if fn.endswith((".ts", ".js", ".mjs", ".cjs")) and not fn.endswith(".d.ts"):
                    try:
                        _SRC_FILES.append(open(os.path.join(root, fn), encoding="utf-8", errors="ignore").read())
                    except OSError:
                        pass
    return _SRC_FILES

def imported(name):
    """True/False if a source dir was given and scanned, None if reachability not assessed."""
    if not src_root:
        return None
    if name not in _import_cache:
        n = re.escape(name)
        pat = re.compile(r"""(require\(\s*['"]%s(/[^'"]*)?['"]\s*\)|from\s+['"]%s(/[^'"]*)?['"]|import\s+['"]%s(/[^'"]*)?['"])""" % (n, n, n))
        _import_cache[name] = any(pat.search(t) for t in _load_sources())
    return _import_cache[name]

ranked, groups = [], defaultdict(list)
for f in rep["findings"]:
    if f["category"] != "known CVE":
        ranked.append({"id": f["id"], "title": f["what"], "category": f["category"],
                       "day1_score": f["score"], "score": f["score"], "confidence": f["confidence"],
                       "reasons": [f"base {f['score']} ({f['risk_level']}); non-CVE finding, not re-scored"],
                       "path": f.get("dependency_path", [])})
        continue
    name, ver = purl_name(f["component"])
    path = f.get("dependency_path") or []
    direct = len(path) == 2                      # ['app', <this package>]
    owner = purl_name(path[1])[0] if len(path) > 1 else name   # top-level package that pulls it in
    node = nodes.get(f["component"], {})
    dev = bool(node.get("dev"))
    used = imported(owner)

    s = float(f["score"]); why = [f"base {f['score']} ({f['risk_level']}) from Day 1 severity"]
    if direct: s += 0.5; why.append("+0.5 direct dependency")
    if f["fix_versions"]: s += 0.5; why.append("+0.5 fix available")
    else: why.append("0 no fix available (accept / replace / escalate)")
    if dev: s -= 1.5; why.append("-1.5 dev-only dependency")
    else: why.append("0 runtime (non-dev) dependency")
    if used is True: s += 1.0; why.append(f"+1.0 '{owner}' is imported in app source (import check, not proof of exploitability)")
    elif used is False: why.append(f"0 no direct import of '{owner}' found (it may still be loaded indirectly, e.g. as a driver)")
    else: why.append("0 reachability not assessed")
    s = round(max(0.0, min(10.0, s)), 1)
    conf = "High" if used is True else "Medium"
    item = {"id": f["id"], "title": f["what"], "category": "known CVE", "advisory": f["advisory"],
            "aliases": f.get("aliases", []), "package": name, "version": ver, "relationship":
            "direct" if direct else "transitive", "day1_score": f["score"], "score": s,
            "confidence": conf, "reasons": why, "path": path, "fix_versions": f["fix_versions"],
            "evidence": [e.get("tool") for e in f.get("verified_evidence", [])]}
    ranked.append(item)
    groups[(name, ver)].append(item)

ranked.sort(key=lambda r: -r["score"])

recs = []
for (name, ver), items in groups.items():
    mins = []
    for it in items:
        newer = [x for x in it["fix_versions"] if vt(x) > vt(ver)]
        same = [x for x in newer if major(x) == major(ver)]
        pick = sorted(same or newer, key=vt)
        if pick: mins.append(pick[0])
    fixable = len(mins) == len(items) and mins
    target = max(mins, key=vt) if fixable else None
    top = max(i["score"] for i in items)
    parent = purl_name(items[0]["path"][1])[0] if len(items[0]["path"]) > 2 else None
    if not target:
        action, compat = f"No fix for all advisories on {name}@{ver}: accept, replace, or escalate", "n/a"
    elif parent:
        action = (f"Upgrade {name} {ver} -> {target} (add npm 'overrides' for {name}, "
                  f"or upgrade parent '{parent}' if a release pulls it in)")
        compat = "low (same major)" if major(target) == major(ver) else "HIGH (major bump, run tests)"
    else:
        action = f"Upgrade {name} {ver} -> {target}"
        compat = "low (same major)" if major(target) == major(ver) else "HIGH (major bump, run tests)"
    recs.append({"package": name, "version": ver, "target_version": target,
                 "findings_cleared": len(items) if target else 0, "findings_total": len(items),
                 "top_score": top, "action": action, "compatibility_impact": compat,
                 "relationship": items[0]["relationship"], "path": items[0]["path"],
                 "note": ("Juice Shop keeps this package old on purpose; upgrade may break its challenges/tests"
                          if name in INTENTIONAL else ""),
                 "rollback": "git revert the fix commit (or restore the previous package-lock.json), then rescan",
                 "evidence_ids": [i["id"] for i in items]})
recs.sort(key=lambda r: (-r["top_score"], -r["findings_cleared"]))

json.dump({"scan_id": rep["id"], "reachability_assessed": bool(src_root),
           "ranking": ranked, "recommendations": recs},
          open(os.path.join(out_dir, "risk_ranking.json"), "w"), indent=2)

print(f"Reachability: {'import check on ' + src_root if src_root else 'NOT assessed (no source dir given)'}")
print(f"{'score':>5}  {'cleared':>7}  {'compat':<28} action")
for r in recs[:12]:
    print(f"{r['top_score']:>5}  {r['findings_cleared']:>3}/{r['findings_total']:<3}  {r['compatibility_impact']:<28} {r['action'][:80]}")
print(f"\nWrote {os.path.join(out_dir, 'risk_ranking.json')}  ({len(ranked)} findings ranked, {len(recs)} package recommendations)")
