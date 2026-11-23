# Supply Chain Guardian: Discover + Detect (stages 1 and 2)

This part of the Bosch "Software Supply Chain Guardian" builds the Guardian's eyes. It turns a repository into an
**SBOM and dependency graph** (Discover). It then produces **evidence-backed findings** (Detect) that the Analyze,
Remediate and Validate stages consume through `findings.json`.

```
Repository ──► Discover ──► sbom.cdx.json + dependency graph ──► Detect ──► findings.json / report.html / SARIF ──► Analyze (AI)
               (lockfiles, pom, Dockerfile,            (CycloneDX 1.5, schema-valid)    (CVEs, malware, typosquats, tampering,
                workflows, external SBOMs)                                               install scripts, images, CI/CD)
```

The stage is pure Python 3.9+ with **no dependencies**. It uses no AI: every finding comes from deterministic data or a
named rule. This keeps the evidence that the Analyze stage reasons over free of hallucinations.

## Quick start

```bash
# full scan of a project (writes ./guardian-out/)
python3 -m guardian scan path/to/project

# the live demo: 8 planted supply-chain attacks, compared against a trusted baseline
python3 tools/make_demo.py
python3 -m guardian scan demo/compromised --baseline demo/baseline/package-lock.json --verify-registry -o out/demo
open out/demo/report.html

# real app (OWASP Juice Shop)
git clone --depth 1 https://github.com/juice-shop/juice-shop && cd juice-shop
npm install --package-lock-only --ignore-scripts --legacy-peer-deps && cd ..
python3 -m guardian scan juice-shop -o out/juice-shop

# no internet on stage? use the bundled offline advisory snapshot
GUARDIAN_OFFLINE=1 python3 -m guardian scan demo/compromised --baseline demo/baseline/package-lock.json

# tests (offline, ~0.1 s)
python3 -m unittest discover -s tests -v
```

Pre-generated outputs for both targets are in `examples/`.

### CLI options (`scan`)

| option | purpose |
|---|---|
| `--baseline X` | A trusted earlier state: `inventory.json`, a CycloneDX/SPDX SBOM, a `package-lock.json`, or a project dir. Enables "what changed" detection. |
| `--sbom f.json` | Merges an external CycloneDX/SPDX SBOM, e.g. a container image SBOM: `syft node:20 -o cyclonedx-json > img.json`. Repeatable. |
| `--image name:tag` | Inspects a container image directly. Needs `syft` on PATH. |
| `--maven-tree t.tgf` | Full Maven transitive tree from `mvn dependency:tree -DoutputType=tgf -DoutputFile=t.tgf`. Run automatically if `mvn` is installed. |
| `--vuln-source` | `auto` (default) tries OSV.dev, then the npm advisory API, then the offline DB. `osv`, `npm` and `offline` force one source. |
| `--vuln-db f.json` | Custom OSV-format offline DB. Build one with `tools/build_offline_db.py`. |
| `--verify-registry` | Compares every lockfile hash with what registry.npmjs.org serves. Also catches packages npm has taken down for malware. |
| `--policy p.json` | Trusted image publishers and action owners (see `policy.example.json`). |
| `--fail-on high` | CI gate: exits 1 if any finding is at or above this severity. |

## What it covers (mapped to the brief)

### 1. Discover
| Requirement | Implementation |
|---|---|
| Direct + transitive deps, names, versions | npm `package-lock.json` / `npm-shrinkwrap.json` v1, v2 and v3, with Node's real `node_modules` resolution, so nested duplicate versions get correct edges. Also handles workspaces, dev/optional/prod scope, `hasInstallScript`, `resolved` and `integrity`. Maven `pom.xml` with properties and dependencyManagement, plus the transitive TGF tree. Python `requirements*.txt`. |
| Container components | Dockerfile `FROM` (ARG substitution, multi-stage aware), docker-compose `image:`, and image package inventories via syft or an imported SBOM. |
| CI/CD workflow | GitHub Actions `uses:` references become components; `run:` lines are kept for script checks. |
| Generate **or consume** an SBOM | Writes **CycloneDX 1.5 JSON**, verified against the official schema in strict mode. Reads CycloneDX and **SPDX 2.x** JSON. |
| Dependency graph | `dependency-graph.json` (nodes and edges), `dependency-graph.dot` (Graphviz), and the CycloneDX `dependencies` section. Each finding carries its root-to-package path(s). |

### 2. Detect
| Risk | Rules | Evidence type |
|---|---|---|
| **Known vulnerabilities** | `VULN-KNOWN`: OSV.dev (all ecosystems) / GitHub Advisory DB via npm. Includes CVSS 3.x score, CVE/GHSA ids, fixed versions (lowest safe version computed from the registry), and the direct dependency that introduced it. | verified |
| **Known malicious packages** | `MAL-KNOWN` (OSV `MAL-*`, "malware/malicious/backdoor" advisories); `REGISTRY-SECURITY-HOLDER`: npm has replaced the package with a security placeholder. | verified |
| **Typosquatting** | `TYPOSQUAT`: Damerau-Levenshtein distance plus homoglyph/separator normalisation against popular npm/PyPI names. Raised to high when the package has an install script, was published recently, has few versions or has no repository. Established packages are suppressed using registry age and version count. | heuristic |
| **Unexpected dependencies** | `UNEXPECTED-LOCK-ONLY-DEP`: in the lockfile but not package.json. `UNEXPECTED-ORPHAN`: nothing depends on it. `LOCKFILE-RANGE-MISMATCH`, `LOCKFILE-STALE`, `REGISTRY-NOT-FOUND` (dependency confusion), `CHANGE-NEW-PACKAGE`, `CHANGE-DOWNGRADE`. | verified |
| **Unsafe install scripts** | `INSTALL-SCRIPT`: reads the actual pre/post-install script from `node_modules` or the registry. Flags pipe-to-shell, remote URLs, `node -e`/eval, base64, credential files, reverse shells, and **env + network = exfiltration**. Recognised native builds (node-gyp, prebuild) are info only. Also `CHANGE-NEW-INSTALL-SCRIPT` and root `INSTALL-SCRIPT-ROOT`. | verified (script text) + heuristic (classification) |
| **Untrusted images** | `IMAGE-UNTRUSTED-SOURCE` (not official or allowlisted), `IMAGE-MUTABLE-TAG` (`latest` or no tag), `IMAGE-NO-DIGEST`, `IMAGE-EOL` (node ≤ 20, python ≤ 3.9 …), `IMAGE-PIPE-TO-SHELL`, `IMAGE-INSECURE-TLS`, `IMAGE-REMOTE-ADD`, `IMAGE-UNPINNED-TOOL`. | verified |
| **Integrity changes** | `CHANGE-INTEGRITY`: the same version has a different hash than the baseline. `INTEGRITY-REGISTRY-MISMATCH`: the lockfile hash differs from the registry's. `CHANGE-SOURCE`: the download host changed. `INTEGRITY-INSECURE-URL` (http). `INTEGRITY-UNTRUSTED-SOURCE` (non-registry host). `INTEGRITY-RESOLVED-MISMATCH`: the tarball URL names a different package or version. `INTEGRITY-MISSING`, `INTEGRITY-WEAK-HASH` (sha1). | verified |
| **Unsafe CI/CD components** | `CICD-UNPINNED-ACTION`: branch refs are high, third-party tags medium, first-party tags low. Also `CICD-SCRIPT-INJECTION` (`${{ github.event.issue.title }}` in `run:`), `CICD-PRT-CHECKOUT`, `CICD-PIPE-TO-SHELL`, `CICD-BROAD-PERMISSIONS`. | verified / heuristic |

## Results

**Demo (`demo/compromised` vs `demo/baseline`)**: all 8 planted attacks are detected. Each one is modelled on a real incident:

| Planted attack | Real incident | Caught by |
|---|---|---|
| event-stream 3.3.4 → 3.3.6 pulls in flatmap-stream | event-stream backdoor, 2018 | MAL-KNOWN, REGISTRY-SECURITY-HOLDER, CHANGE-NEW-PACKAGE (path: shop-api › event-stream › flatmap-stream) |
| `crossenv` typo with an env-stealing postinstall | crossenv, 2017 | TYPOSQUAT, INSTALL-SCRIPT (critical: exfiltration), REGISTRY-SECURITY-HOLDER |
| lodash 4.17.15 hash swapped in the lockfile | lockfile tampering | CHANGE-INTEGRITY, INTEGRITY-REGISTRY-MISMATCH |
| minimist re-pointed to a `http://` look-alike mirror | lockfile injection | INTEGRITY-INSECURE-URL, CHANGE-SOURCE |
| Lockfile-only dependency from a private host, no hash | dependency confusion | UNEXPECTED-LOCK-ONLY-DEP, INTEGRITY-MISSING, INTEGRITY-UNTRUSTED-SOURCE |
| Orphan ua-parser-js@0.7.29 | ua-parser-js hijack, 2021 | MAL-KNOWN, UNEXPECTED-ORPHAN |
| `FROM node:latest`, `fastbuilds/node-runtime`, `curl \| bash` | untrusted image | IMAGE-MUTABLE-TAG, IMAGE-UNTRUSTED-SOURCE, IMAGE-PIPE-TO-SHELL |
| Action pinned to `@main`, issue-title injection | CI/CD compromise | CICD-UNPINNED-ACTION, CICD-SCRIPT-INJECTION |

The **clean baseline** produces **zero** integrity, typosquat, unexpected-dependency or malware findings (unit-tested).

**OWASP Juice Shop** (real app): 1,143 components (133 direct, 1,010 transitive, depth 10, plus 10 images and
25 actions). It finds 78 issues, including `sanitize-html › lodash@2.4.2`, `express-jwt › jsonwebtoken@0.1.0`
(verification bypass), `marsdb` command injection, an action pinned to `@main`, and `curl … | sh` in the release workflow.

## Hand-off contract for the Analyze stage (`findings.json`, schema `guardian.findings/v1`)

```jsonc
{
  "project": "shop-api@1.4.0",
  "inventory": {"components": 157, "direct": 14, "transitive": 143, "by_scope": {...}, "max_depth": 6},
  "vulnerability_source": "osv.dev",
  "baseline_diff": {"added": 4, "removed": 0, "version_changed": 1, "added_list": [...]},
  "coverage_notes": ["what was NOT analysed and why"],
  "findings": [{
    "id": "GRD-1a2b3c4d5e",              // stable across runs (use for tracking / dedupe)
    "rule": "VULN-KNOWN",
    "category": "vulnerability",          // vulnerability | malicious-package | typosquat | unexpected-dependency |
                                          // install-script | untrusted-image | integrity | cicd
    "severity": "high",                   // INITIAL level; Analyze re-scores with reachability/exposure
    "confidence": "high",
    "evidence_type": "verified",          // verified = deterministic data, heuristic = pattern match
    "title": "...",
    "component": {"id": "pkg:npm/lodash@4.17.15", "name": "lodash", "version": "4.17.15",
                  "ecosystem": "npm", "direct": true, "scope": "prod"},   // scope: prod|dev|optional|build|ci
    "dependency_paths": [["shop-api@1.4.0", "lodash@4.17.15"]],
    "evidence": [{"kind": "advisory", "source": "osv.dev", "detail": "...", "location": "node_modules/lodash"}],
    "identifiers": ["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"],
    "references": ["https://github.com/advisories/..."],
    "fix": {"fixed_versions": ["4.17.21"], "available": true, "introduced_via": ["lodash@4.17.15"], "cvss_score": 7.2}
  }]
}
```

Notes for the next stages:
- **Prioritise:** `component.scope` (prod vs dev/ci), `component.direct`, path length and `fix.cvss_score` are ready-made inputs for reachability and exposure scoring.
- **Remediate:** `fix.fixed_versions` and `fix.introduced_via` say *which* direct dependency to bump.
- **Validate:** run Discover on the fixed branch, then `scan --baseline <old sbom.cdx.json>`. The diff shows exactly what changed, and the rescan shows the risk reduction. The finding `id` is stable, so you can mark findings as resolved.
- **AI prompts:** quote `evidence[]` verbatim and keep `evidence_type` so the model separates verified facts from heuristics.
- `findings.sarif` uploads to GitHub code scanning as-is.

## Layout
```
guardian/discover/   npm.py, maven.py, python_reqs.py, containers.py (Dockerfile/compose/Actions), sbom.py (CycloneDX/SPDX I/O)
guardian/detect/     vulns.py (OSV/npm/offline + CVSS), packages.py (typosquat, install scripts, integrity, registry),
                     changes.py (manifest consistency, baseline diff), infra.py (images, Dockerfile, CI/CD)
guardian/data/       popular-npm.txt, popular-pypi.txt, known-legit.txt, offline-advisories.json
tools/               make_demo.py (planted attacks), build_offline_db.py
tests/               offline unit + end-to-end tests
examples/            generated output for Juice Shop and the demo
```

## Known limitations
- Maven transitive deps need `mvn` or a TGF file. Python transitive deps need a lock or SBOM (pip freeze). Both are reported in `coverage_notes`.
- Install-script contents are read from `node_modules` or the registry; for private packages without either, only the `hasInstallScript` flag is available.
- The typosquat popular-name list is curated (~370 npm, ~90 PyPI names). Extend `guardian/data/popular-*.txt` as needed.
- EOL image data is a static table (as of Nov 2026).
- Image *signature* verification (Cosign/Sigstore) is a stretch goal and not implemented here.
- The offline DB is a snapshot. Use `--vuln-source osv` or `auto` for current data.
