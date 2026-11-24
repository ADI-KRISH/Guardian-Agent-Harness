#!/usr/bin/env python3
"""Day 2: turn risk_ranking.json into a remediation plan (recommendations only, nothing is applied).

Usage:
  python3 day2/recommend_fixes.py day2/output/risk_ranking.json [--out day2/output]

Writes remediation_plan.json (machine-readable) and remediation_plan.md (human-readable).
Rules: fix versions come from scanner data only; compatibility notes are rule-based and
labelled 'inferred'; every item needs human approval before anything is applied.
"""
import json, re, sys, os
from collections import defaultdict, Counter

args = [a for a in sys.argv[1:] if not a.startswith("--")]
out_dir = "day2/output"
if "--out" in sys.argv:
    out_dir = sys.argv[sys.argv.index("--out") + 1]
    args = [a for a in args if a != out_dir]
src = args[0]
os.makedirs(out_dir, exist_ok=True)
data = json.load(open(src))
ranking = data["ranking"]

SEV = {9.5: "Critical", 8.0: "High", 5.5: "Medium", 2.5: "Low"}
def tier(day1):  # Day 1 severity of the finding
    return "Critical" if day1 >= 9 else "High" if day1 >= 7 else "Medium" if day1 >= 4 else "Low"
TIER_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

INTENTIONAL = {"jsonwebtoken", "express-jwt", "sanitize-html", "marsdb", "crypto-js", "lodash",
               "notevil", "hbs", "base64url", "jws", "moment"}
DEMO_ROLE = {"ws": "hero_fix (safe minor bump)", "tar": "one_fix_many_findings",
             "marsdb": "no_fix_escalate", "jsonwebtoken@0.4.0": "compatibility_trap"}

def purl_name(p):
    m = re.match(r"pkg:npm/(.+?)@([^#]+)", p or "")
    return (m.group(1).replace("%40", "@"), m.group(2)) if m else (None, None)

def manifest_of(path):
    last = path[-1] if path else ""
    return "frontend/package.json" if "#frontend/package-lock.json#" in last else "package.json"

def vt(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3]) or (0,)

def distance(cur, tgt):
    c, t = vt(cur), vt(tgt)
    if t[0] != c[0]:
        return "major"
    if (t + (0, 0, 0))[1] != (c + (0, 0, 0))[1]:
        return "minor"
    return "patch"

COMPAT = {"patch": "LOW", "minor": "LOW-MEDIUM", "major": "HIGH"}

# ---------- known CVEs: one recommendation per package version ----------
groups = defaultdict(list)
for r in ranking:
    if r["category"] == "known CVE":
        groups[(r["package"], r["version"])].append(r)

items = []
for (name, ver), fs in groups.items():
    mins = []
    for f in fs:
        newer = [x for x in f["fix_versions"] if vt(x) > vt(ver)]
        same = [x for x in newer if vt(x)[0] == vt(ver)[0]]
        pick = sorted(same or newer, key=vt)
        if pick:
            mins.append(pick[0])
    target = max(mins, key=vt) if mins and len(mins) == len(fs) else None
    partial = (len(mins) > 0 and target is None)
    rel = fs[0]["relationship"]
    parent = purl_name(fs[0]["path"][1])[0] if len(fs[0]["path"]) > 2 else None
    manifest = manifest_of(fs[0]["path"])
    sev_counts = Counter(tier(f["day1_score"]) for f in fs)
    top_tier = min((tier(f["day1_score"]) for f in fs), key=lambda t: TIER_ORDER[t])
    top_score = max(f["score"] for f in fs)
    key = name if name in DEMO_ROLE else f"{name}@{ver}"

    it = {"package": name, "current_version": ver, "target_version": target, "tier": top_tier,
          "relationship": rel, "parent": parent, "manifest": manifest,
          "dependency_path": [purl_name(p)[0] and f"{purl_name(p)[0]}@{purl_name(p)[1]}" or p for p in fs[0]["path"]],
          "top_risk_score": top_score,
          "intentionally_old_in_juice_shop": name in INTENTIONAL,
          "demo_role": DEMO_ROLE.get(key, DEMO_ROLE.get(name, "")),
          "evidence_ids": [f["id"] for f in fs],
          "advisories": sorted({f["advisory"] for f in fs}),
          "verified": {"fix_versions_from": "OSV via GuardianAI report",
                       "fixed_versions": sorted({x for f in fs for x in f["fix_versions"]}, key=vt)},
          "approval": {"required": True, "status": "pending", "approved_by": None, "approved_at": None}}

    if target:
        dist = distance(ver, target)
        it["compatibility_impact"] = COMPAT[dist] + (" (0.x -> stable: API very likely changed)" if vt(ver)[0] == 0 and dist == "major" else "")
        it["version_jump"] = dist
        it["expected_risk_reduction"] = {"findings_cleared": len(fs),
            "by_severity": dict(sev_counts), "advisories_cleared": len({f["advisory"] for f in fs})}
        if rel == "direct":
            it["action"] = "upgrade"
            it["how"] = (f"In {manifest}, set dependency {name} to {target}, then regenerate the lockfile.")
            it["change"] = {"file": manifest, "set": {"dependencies": {name: target}}}
        else:
            it["action"] = "override"
            it["how"] = (f"First check whether a newer '{parent}' release already depends on a fixed {name}. "
                         f"If not, add a scoped npm override in {manifest} so only {parent}'s copy changes.")
            it["change"] = {"file": manifest, "set": {"overrides": {parent: {name: target}}}}
        it["commands"] = [
            "git checkout -b fix/%s-%s" % (name.replace("@", "").replace("/", "-"), target),
            "# edit %s as shown in 'change', then:" % manifest,
            "npm install --package-lock-only --ignore-scripts --legacy-peer-deps" if manifest == "package.json"
            else "cd frontend && npm install --package-lock-only --ignore-scripts --legacy-peer-deps",
            "python3.12 -m guardian scan <juice-shop-path> --output day2/output/after_%s.json" % name.replace("@", "").replace("/", "-"),
        ]
        it["rollback"] = f"git revert the fix commit (or `git checkout -- {manifest} package-lock.json`), then rescan to confirm the original state."
        it["verify_after_fix"] = {"rescan": "none of evidence_ids should be present",
                                  "also_check": "no new findings introduced; build and tests pass"}
    else:
        it["action"] = "escalate_or_accept"
        it["compatibility_impact"] = "n/a (no fixed version published for every advisory)"
        it["expected_risk_reduction"] = {"findings_cleared": 0, "by_severity": {}, "advisories_cleared": 0}
        it["how"] = ("No upstream fix covers every advisory. Human decision needed: (a) remove or replace the package "
                     "(needs code changes), (b) accept with a written reason, owner and expiry date, or (c) escalate to the package maintainers/security lead.")
        it["rollback"] = "n/a (no change proposed)"
        it["verify_after_fix"] = {"rescan": "finding stays open until a decision is recorded"}
    items.append(it)

# Parent-first insight: if a transitive package hangs under a vulnerable direct package that has a fix,
# upgrading that parent may remove the old copy entirely (verify by rescanning before adding an override).
direct_targets = {i["package"]: i["target_version"] for i in items
                  if i["relationship"] == "direct" and i["target_version"]}
for i in items:
    if i["relationship"] == "transitive" and i["parent"] in direct_targets:
        i["parent_upgrade_may_clear"] = {"parent": i["parent"], "parent_target": direct_targets[i["parent"]],
            "note": "Inferred: upgrade the parent first, rescan, and only add this override if the finding remains."}

items.sort(key=lambda i: (TIER_ORDER[i["tier"]], -i["top_risk_score"],
                          -i["expected_risk_reduction"]["findings_cleared"]))

# ---------- non-CVE findings: grouped by what they are ----------
non = [r for r in ranking if r["category"] != "known CVE"]
def group_of(t):
    t = t.lower()
    if "not pinned to an immutable commit" in t: return ("pin", "Pin GitHub Actions to full commit SHAs",
        "Replace tag/branch refs (e.g. @v4, @main) with the full commit SHA, keeping the version in a comment.")
    if "digest-pinned" in t: return ("pin", "Pin container base images to digests",
        "Use image@sha256:<digest> for each FROM line; update deliberately via a reviewed change.")
    if "privileged workflow" in t: return ("review", "Review privileged workflow",
        "Check pull_request_target / write permissions; restrict permissions and never run untrusted code with secrets.")
    if "install script" in t or "postinstall" in t: return ("allowlist_or_review", "Install scripts on dependencies",
        "Common for native packages (esbuild, fsevents, sqlite3). Review once, then allow-list known ones; keep --ignore-scripts for analysis.")
    if "outbound network" in t or "downloads and executes" in t: return ("escalate", "Heuristic source/backdoor signals",
        "Static candidates, not proof. Human review of the flagged files; likely expected in a deliberately vulnerable app.")
    return ("review", t[:60], "Review manually.")
ng = defaultdict(list)
for r in non:
    ng[group_of(r["title"])].append(r)
non_cve = [{"action": a, "title": t, "recommendation": how, "count": len(rs),
            "evidence_ids": [r["id"] for r in rs],
            "verified_or_inferred": "heuristic (static rule), not proof of compromise",
            "approval": {"required": True, "status": "pending"}} for (a, t, how), rs in ng.items()]

plan = {"source": os.path.basename(src), "scan_id": data.get("scan_id"),
        "reachability_assessed": data.get("reachability_assessed"),
        "note": "Recommendations only. Nothing is applied until a human approves. "
                "Fix versions are verified (scanner data); compatibility and effort notes are rule-based and inferred.",
        "package_recommendations": items, "non_cve_recommendations": non_cve}
json.dump(plan, open(os.path.join(out_dir, "remediation_plan.json"), "w"), indent=2)

# ---------- readable summary ----------
L = ["# Remediation plan (recommendations only)", "",
     f"Scan {plan['scan_id']} | reachability assessed: {plan['reachability_assessed']} | every item needs human approval", ""]
for t in ["Critical", "High", "Medium", "Low"]:
    rows = [i for i in items if i["tier"] == t]
    if not rows: continue
    L += [f"## {t} packages", "", "| # | Package | Action | Clears | Compatibility | Notes |", "|---|---|---|---|---|---|"]
    for n, i in enumerate(rows, 1):
        act = (f"{i['action']} -> {i['target_version']}" if i["target_version"] else i["action"])
        notes = []
        if i["intentionally_old_in_juice_shop"]: notes.append("intentionally old in Juice Shop")
        if i["demo_role"]: notes.append("demo: " + i["demo_role"])
        if i.get("parent_upgrade_may_clear"): notes.append("try parent first: " + i["parent"] + " -> " + i["parent_upgrade_may_clear"]["parent_target"])
        L.append(f"| {n} | {i['package']}@{i['current_version']} ({i['relationship']}) | {act} | "
                 f"{i['expected_risk_reduction']['findings_cleared']}/{len(i['evidence_ids'])} | {i['compatibility_impact'].split(' (')[0]} | {'; '.join(notes)} |")
    L.append("")
L += ["## Non-CVE recommendations", "", "| Action | What | Count |", "|---|---|---|"]
L += [f"| {n['action']} | {n['title']} | {n['count']} |" for n in non_cve]
open(os.path.join(out_dir, "remediation_plan.md"), "w").write("\n".join(L) + "\n")

crit = [i for i in items if i["tier"] == "Critical"]
print(f"{len(items)} package recommendations ({len(crit)} Critical), {len(non_cve)} non-CVE groups")
for i in items[:10]:
    tgt = i["target_version"] or "no fix"
    print(f"  [{i['tier']:<8}] {i['package']}@{i['current_version']} -> {tgt:<10} {i['action']:<18} clears {i['expected_risk_reduction']['findings_cleared']}/{len(i['evidence_ids'])}  compat {i['compatibility_impact'].split(' (')[0]}")
print(f"Wrote {out_dir}/remediation_plan.json and remediation_plan.md")
