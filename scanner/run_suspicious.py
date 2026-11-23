import json, sys
from pathlib import Path
import install_script_detector as inst
import lockfile_diff_detector as lock
import typosquat_detector as typo

def main(repo, base, new, out):
    # Install scripts already present in the base are not "changes", so drop them
    seen = {(f["title"], f["evidence"][0]["detail"]) for f in inst.scan(repo, base)}
    findings = [f for f in inst.scan(repo, new) if (f["title"], f["evidence"][0]["detail"]) not in seen]
    findings += lock.scan(repo, base, new)
    findings += typo.scan(repo, base, new)
    for i, f in enumerate(findings, 1):
        f["id"] = f"S-{i:03d}"
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"{len(findings)} findings -> {out}")
    for f in findings:
        print(f"  {f['id']}  {f['severity']:<7} {f['title']}  [{f['component']['name']}]")

if __name__ == "__main__":
    main(*sys.argv[1:5])
