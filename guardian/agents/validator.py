"""Validation agent: prove (or disprove) that an APPROVED fix works, in a sandbox.

Flow: local sandbox branch -> apply the edit -> refresh the lockfile (no package code runs on the host) -> docker build of the
dependency tree (--ignore-scripts) -> checks inside a no-network container -> optional project tests -> rescan -> before/after diff.
Never merges, pushes or deploys: the result is a patch and a report for a human.
"""
from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path

from .. import config
from ..tools import git, run, scanners
from . import change, evidence, fixer, verifier, vuln
from .discovery import GEN_MARK, snapshot

NPM_DOCKERFILE = """FROM {image}
WORKDIR /app
COPY package.json package-lock.json* ./
RUN {install}
"""
PIP_DOCKERFILE = """FROM {image}
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
"""
FULL_DOCKERFILE = """FROM {image}
WORKDIR /app
COPY . .
RUN {install}
"""


def _safe(ref: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", ref)


def _vkey(f: dict):
    """Identity of a finding across the fix: a CVE on a package, wherever its version moved to."""
    if f["type"] == "known_vulnerability":
        name = f["component"].split(":", 1)[-1].rsplit("@", 1)[0]
        return ("vuln", f["id"], name)
    return ("fp", f["fingerprint"])


def sbom_diff(before: dict, after: dict) -> dict:
    def by_name(pk):
        out: dict = {}
        for p in pk.values():
            out.setdefault((p["ecosystem"], p["name"]), set()).add(p["version"])
        return out
    b, a = by_name(before), by_name(after)
    added = sorted(f"{e}:{n}@{'/'.join(sorted(v))}" for (e, n), v in a.items() if (e, n) not in b)
    removed = sorted(f"{e}:{n}@{'/'.join(sorted(v))}" for (e, n), v in b.items() if (e, n) not in a)
    updated = sorted(f"{e}:{n} {'/'.join(sorted(b[(e, n)]))} -> {'/'.join(sorted(a[(e, n)]))}" for (e, n) in a if (e, n) in b and a[(e, n)] != b[(e, n)])
    return {"added": added, "removed": removed, "updated": updated}


def decide_verdict(steps: list[dict], target_gone: bool, blocking: list[dict]) -> tuple[str, str]:
    failed = [s for s in steps if s["status"] == "fail"]
    if failed:
        return "not-verified", f"step '{failed[0]['name']}' failed: {failed[0]['detail'][:160]}"
    if not target_gone:
        return "not-verified", "the targeted finding is still present after the fix"
    if blocking:
        return "not-verified", f"the fix introduces {len(blocking)} new High/Critical finding(s): " + ", ".join(b["id"] for b in blocking[:4])
    gaps = [s["name"] for s in steps if s["status"] == "skipped"]
    if gaps:
        return "verified-with-gaps", "installs, loads and rescans clean; not run: " + ", ".join(gaps)
    return "verified", "installs, loads, passes the project tests and the rescan shows the finding gone with nothing new at High or Critical"


def validate(prop: dict, repo: Path, report: dict, inventory: dict, mem, out_dir: Path, test_cmd: str = "", log=print) -> dict:
    t0, rid, project = time.time(), f"fix-{prop['id']}", prop["project"]
    steps: list[dict] = []
    vcfg = config.load(None)["validate"]            # operator-level settings only: a scanned repo cannot choose images or commands
    test_cmd = test_cmd or vcfg["test"]

    def step(name: str, status: str, detail: str) -> None:
        steps.append({"name": name, "status": status, "detail": detail})
        mem.decide(rid, project, "validation-agent", f"{name}: {status}", detail[:400], rule="sandbox-validation")
        log(f"  [validation-agent] {name}: {status} - {detail[:140]}")

    sha, branch, eco, name = prop["head_sha"], f"guardian/{prop['id'].lower()}", prop["ecosystem"], prop["package"]
    sb = config.WORKSPACE / "sandbox" / project / prop["id"]
    ctx = config.WORKSPACE / "sandbox" / project / f"{prop['id']}-ctx"
    image, test_image = f"guardian-sandbox/{project.lower()}:{prop['id'].lower()}", f"guardian-sandbox/{project.lower()}:{prop['id'].lower()}-test"
    out_dir.mkdir(parents=True, exist_ok=True)
    result: dict = {"proposal": prop, "branch": branch, "sandbox": str(sb), "steps": steps}
    try:
        if not scanners.docker_available():
            step("docker", "fail", "Docker is not running: start Docker Desktop. Nothing was built.")
            raise RuntimeError("docker")
        git.branch_worktree(repo, sha, sb, branch)
        step("sandbox branch", "pass", f"{branch} at {sha[:10]} in {sb} (local only, never pushed)")

        lock_rel = prop["lockfile"]
        head_dir = config.WORKSPACE / "checkouts" / project / _safe(prop["head_ref"])
        if eco == "npm":   # start from the exact lockfile the scan used so before/after differ only by the fix
            mdir = Path(prop["file"]).parent
            for rel in (lock_rel, str(mdir / GEN_MARK)):
                if (head_dir / rel).exists() and not (sb / rel).exists():
                    shutil.copy2(head_dir / rel, sb / rel)
        files = fixer.apply_edit(prop, sb)
        step("apply fix", "pass", prop["change"])
        if eco == "npm":
            r = run("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--legacy-peer-deps"],
                    cwd=sb / Path(prop["file"]).parent, timeout=900)
            step("update lockfile", "pass" if r.ok else "fail", "npm install --package-lock-only --ignore-scripts (no package code runs)" if r.ok else r.stderr[-300:])
            if not r.ok:
                raise RuntimeError("lockfile")
            if run("git", ["-C", str(sb), "ls-files", "--error-unmatch", lock_rel]).ok:
                files.append(lock_rel)
        committed = git.commit_paths(sb, files, f"guardian: {prop['change']} ({prop['id']})")
        patch = git.patch_since(sb, sha)
        (out_dir / "patch.diff").write_text(patch, encoding="utf-8")
        step("commit on sandbox branch", "pass" if committed else "fail", f"{len(patch.splitlines())} line patch saved as patch.diff (nothing merged or pushed)")

        # ---- build the dependency tree in a container (no package scripts) ----
        shutil.rmtree(ctx, ignore_errors=True)
        ctx.mkdir(parents=True)
        if eco == "npm":
            mdir = sb / Path(prop["file"]).parent
            for fn in ("package.json", "package-lock.json"):   # .npmrc is not copied: it may hold registry credentials
                if (mdir / fn).exists():
                    shutil.copy2(mdir / fn, ctx / fn)
            install = "npm ci --ignore-scripts --no-audit --no-fund --legacy-peer-deps" if (ctx / "package-lock.json").exists() else \
                      "npm install --ignore-scripts --no-audit --no-fund --legacy-peer-deps"
            (ctx / "Dockerfile").write_text(NPM_DOCKERFILE.format(image=vcfg["node_image"], install=install), encoding="utf-8")
        else:
            shutil.copy2(sb / prop["file"], ctx / "requirements.txt")
            (ctx / "Dockerfile").write_text(PIP_DOCKERFILE.format(image=vcfg["python_image"]), encoding="utf-8")
        b = scanners.docker_build(ctx, image, timeout=vcfg["build_timeout_s"])
        step("docker build", "pass" if b.ok else "fail",
             f"dependency tree installed in {vcfg['node_image' if eco == 'npm' else 'python_image']}" if b.ok else b.stderr[-400:])
        if not b.ok:
            raise RuntimeError("build")

        # ---- checks inside the no-network container ----
        if eco == "npm":
            r = scanners.docker_run_sandboxed(image, ["npm", "ls", name, "--all"], timeout=120)
            found = sorted(set(re.findall(rf"{re.escape(name)}@(\d+\.\d+\.\d+\S*)", r.stdout)), key=fixer.vt)
        else:
            r = scanners.docker_run_sandboxed(image, ["pip", "show", name], timeout=120)
            found = re.findall(r"^Version:\s*(\S+)", r.stdout, re.M)
        ok = bool(found) and all(fixer.vt(v) >= fixer.vt(prop["to"]) for v in found)
        step("resolved version", "pass" if ok else "fail", f"{name} resolves to {', '.join(found) or 'nothing'} (wanted >= {prop['to']})")
        if eco == "npm":
            js = f"try{{require('{name}');console.log('LOADED')}}catch(e){{if(e.code==='ERR_REQUIRE_ESM'){{console.log('ESM_ONLY')}}else{{console.log('LOAD_FAILED '+e.message);process.exit(1)}}}}"
            r = scanners.docker_run_sandboxed(image, ["node", "-e", js], timeout=60)
            if "ESM_ONLY" in r.stdout:
                step("smoke import", "skipped", f"{name} is ESM-only, cannot be require()d")
            else:
                step("smoke import", "pass" if r.ok and "LOADED" in r.stdout else "fail", (r.stdout.strip() or r.stderr.strip())[-200:])
        else:
            step("smoke import", "skipped", "no generic import check for Python distributions (module name differs from package name)")

        # ---- the project's own tests (operator-supplied command) ----
        if test_cmd and eco == "npm":
            full = sb / ".guardian.Dockerfile"
            (sb / ".dockerignore").write_text("node_modules\n.git\n", encoding="utf-8")
            full.write_text(FULL_DOCKERFILE.format(image=vcfg["node_image"], install=install), encoding="utf-8")
            tb = scanners.docker_build(sb, test_image, dockerfile=full, timeout=vcfg["build_timeout_s"])
            if tb.ok:
                tr = scanners.docker_run_sandboxed(test_image, ["sh", "-c", test_cmd], timeout=vcfg["test_timeout_s"], read_only=False)
                step("project tests", "pass" if tr.ok else "fail", f"`{test_cmd}` rc={tr.returncode}: {(tr.stdout + tr.stderr)[-250:].strip()}")
            else:
                step("project tests", "fail", f"test image build failed: {tb.stderr[-300:]}")
        else:
            step("project tests", "skipped", "no project test command configured (set GUARDIAN_VALIDATE_TEST or pass --test); "
                 "the fix is not proven against the application's own behaviour" if eco == "npm" else "test step is implemented for npm projects only")

        # ---- rescan the patched tree and compare ----
        after = snapshot(sb, run_syft=True)
        before_snap = {"packages": inventory["packages"], "graph": inventory["graph"], "roots": inventory["roots"]}
        vf, _ = vuln.scan(sb, after, before_snap)
        cs, cf = change.diff(before_snap, after, config.load(sb))
        new_all, _ = verifier.verify(vf + cf, sb, after)
        evidence.score(new_all, after)
        before_v = [f for f in report["findings"] if f["type"] == "known_vulnerability" and not f.get("suppressed_by")]
        bk, ak = {_vkey(f) for f in before_v}, {_vkey(f) for f in new_all if f["type"] == "known_vulnerability"}
        target_ids = set(prop["resolves"])
        target_gone = bool(target_ids) and all(_vkey(f) not in ak for f in before_v if f["id"] in target_ids)
        bc, ac = {(f["id"], f["component"]) for f in before_v}, {(f["id"], f["component"]) for f in new_all if f["type"] == "known_vulnerability"}
        resolved = [f for f in before_v if (f["id"], f["component"]) not in ac]          # that exact package version no longer has it
        remaining = [f for f in new_all if f["type"] == "known_vulnerability"]
        introduced = [f for f in new_all if (f["id"], f["component"]) not in bc]         # incl. a bump onto a still-vulnerable version
        blocking = [f for f in introduced if f["risk_level"] in ("Critical", "High")]
        lv = lambda fs: {k: sum(1 for f in fs if f["risk_level"] == k) for k in ("Critical", "High", "Medium", "Low")}  # noqa: E731
        brief = lambda f: {"id": f["id"], "title": f["title"][:120], "risk_level": f["risk_level"], "score": f["score"]}  # noqa: E731
        step("rescan", "pass", f"known vulnerabilities {len(before_v)} -> {len(remaining)}; {len(resolved)} resolved; "
             f"{len(introduced)} new finding(s), {len(blocking)} at High/Critical")
        (out_dir / "sbom.after.cdx.json").write_text(json.dumps(after.get("sbom") or {}, indent=1), encoding="utf-8")
        result.update(
            before={"packages": len(inventory["packages"]), "known_vulnerabilities": lv(before_v), "count": len(before_v)},
            after={"packages": len(after["packages"]), "known_vulnerabilities": lv(remaining), "count": len(remaining)},
            resolved=[brief(f) for f in resolved], remaining=[brief(f) for f in remaining], introduced=[brief(f) for f in introduced],
            sbom_diff=sbom_diff(inventory["packages"], after["packages"]), target_gone=target_gone)
        v, why = decide_verdict(steps, target_gone, blocking)
    except Exception as e:  # noqa: BLE001 - a failed validation is a result to report, not a crash
        if not any(s["status"] == "fail" for s in steps):
            step("validation", "fail", f"{type(e).__name__}: {e}")
        v, why = decide_verdict(steps, False, [])
    finally:
        for tag in (image, test_image):
            scanners.docker_rmi(tag)
    result.update(verdict=v, verdict_reason=why, seconds=round(time.time() - t0, 1))
    mem.decide(rid, project, "validation-agent", f"verdict {v}", why, {"proposal": prop["id"]}, rule="verified-remediation")
    return result
