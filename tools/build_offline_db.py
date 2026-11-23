"""Snapshot advisories for one or more projects into an OSV-format offline DB.

  python tools/build_offline_db.py demo/compromised demo/baseline -o guardian/data/offline-advisories.json

Uses OSV.dev when reachable, otherwise the npm registry advisory API. The result lets
`guardian scan --vuln-source offline` run in air-gapped CI or on stage with no Wi-Fi.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from guardian.discover import discover  # noqa: E402
from guardian.detect import vulns  # noqa: E402
from guardian import net  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("projects", nargs="+", type=Path)
ap.add_argument("-o", "--out", type=Path, required=True)
a = ap.parse_args()

db = {}
for proj in a.projects:
    inv, _ = discover(proj)
    comps = vulns._pkgs(inv)
    try:
        hits = vulns._osv_online(comps)
    except net.NetError:
        hits = vulns._npm_bulk(comps)
    for cid, vs in hits.items():
        for v in vs:
            if v["id"] in db:
                # merge affected entries for other packages
                names = {x["package"]["name"] for x in db[v["id"]]["affected"]}
                db[v["id"]]["affected"] += [x for x in v["affected"] if x["package"]["name"] not in names]
            else:
                db[v["id"]] = v
a.out.write_text(json.dumps(sorted(db.values(), key=lambda x: x["id"]), indent=1))
print(f"wrote {len(db)} advisories to {a.out}")
