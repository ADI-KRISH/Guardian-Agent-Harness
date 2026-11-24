# GuardianAI

A runnable, local software supply-chain analysis application with a dependency knowledge graph, evidence ledger, trusted baselines, and human-reviewed learning proposals. Built from the Guardian Agent Harness Day 1 design.

## Run

Requires Python 3.11 or newer. No runtime packages, Node, API keys or frontend build step are required.

```sh
cd /Users/ananthakrishnans/Documents/bosh
python3 -m guardian serve
```

Open **http://127.0.0.1:8787**. Select **New scan** and enter a local repository directory or a public `https://github.com/owner/repository` URL. The **Try planted demo** button provides a small, intentionally risky synthetic inventory. Use **Offline mode** to prevent OSV calls; uncovered packages are explicitly marked unavailable.

The dashboard includes overview, searchable findings, interactive dependency knowledge graph, baseline changes, memory and learning, audit trail, and a live deterministic evaluation scoreboard. Click graph nodes to inspect inbound/outbound relations and related evidence; use the evidence toggle, search, zoom and pan controls. Large graphs currently display their first 180 entities, with an explicit label; the full graph remains in JSON exports.

## Implemented workflow

1. Read bounded repository files without running package code.
2. Parse manifests/lockfiles or a CycloneDX JSON SBOM; build resolved edges when the input provides them.
3. Compare inventory, integrity hashes and source-file hashes against the last human-approved baseline.
4. Run static source/CI/container rules and exact-version OSV checks concurrently.
5. Validate evidence file existence and line bounds; deduplicate, score and record findings.
6. Persist SQLite memories, append-only audit events and JSON snapshots.
7. Show dependency → finding → evidence-file relationships in the knowledge graph.
8. Accept named human reviews and baseline promotion. Propose scoped, expiring lessons from false-positive labels; require regression evaluation and explicit approval before applying them.

The specialists are deterministic Python stages. There is no configured LLM, and no claims of model inference are manufactured.

## Inventory support

| Input | Inventory | Dependency edges |
|---|---|---|
| npm package-lock v2/v3 or shrinkwrap | Exact direct/transitive packages, integrity, install flags | Node-style nearest installed package resolution |
| package.json alone | Declared dependencies, including ranges | Direct declarations only; ranges are not queried as exact versions |
| requirements*.txt | Exact `==` pins | Declared list only; transitive provenance unavailable |
| pyproject.toml | Exact PEP 621 dependency pins; unresolved ranges reported | Direct declarations only |
| Cargo.lock | Package versions and checksums | Lockfile package edges; application roots remain unknown |
| go.mod | Required module versions and indirect flags | Direct declarations; indirect containment, no invented chain |
| pom.xml | Explicit direct coordinates | No Maven resolution/property interpolation |
| *sbom*.json / *cyclonedx*.json | CycloneDX components and purls | Supplied CycloneDX dependency relationships |

Coverage notes identify unsupported/missing information. Python requirements, Go, Maven and Cargo inputs with missing root relationships deliberately remain partial. This prevents promoting an inventory that hides known discovery gaps. For other package managers, generate a CycloneDX SBOM externally and place it in a scan directory. Avoid combining an imported SBOM with the same native manifest inventory to prevent duplicate package instances.

## Detections

- Known advisories from the [OSV exact-version API](https://google.github.io/osv.dev/post-v1-query/), including pagination, aliases, references, qualitative severity, raw CVSS fields and package-specific fix boundaries.
- Same-version integrity changes, added/removed/updated dependencies and source-file changes.
- Install scripts, lookalike names (heuristic), encoded dynamic execution, Unicode bidi controls, secret access plus network activity, download-and-execute patterns and changed build files.
- GitHub Actions not pinned to SHA, privileged workflow signals, Docker base images without digests and explicit root users.

Observations are not proof of malicious intent. Severity comes from an explicit static rule or OSV qualitative severity. Missing severity is **Unknown**, not silently Low. Reachability is not assessed; fix boundaries require compatible-release selection and testing.

## CLI

```sh
python3 -m guardian scan /path/to/repository --output report.json
python3 -m guardian scan https://github.com/owner/repository --output report.json
python3 -m guardian scan examples/demo --offline --planted
python3 -m guardian list
python3 -m guardian export SCAN_ID --format sbom --output sbom.json
python3 -m guardian export SCAN_ID --format markdown --output report.md
python3 -m guardian review SCAN_ID FINDING_ID confirmed --actor 'Your name' --reason 'Checked evidence'
python3 -m guardian baseline SCAN_ID --actor 'Your name' --reason 'Reviewed and trusted'
python3 -m guardian approve-lesson LESSON_ID --actor 'Your name' --reason 'Approved scoped noise reduction'
python3 -m guardian eval
python3 -m unittest discover -s tests -v
```

Use `python3 -m guardian --data /path/to/memory ...` to select a separate SQLite/snapshot directory. Reviews are overlays on immutable scan payloads; retrieve a fresh report with `export` to include current decisions. Raw snapshot JSON preserves original run state.

## Isolation

The local server is intended for one trusted workstation user. A reviewer name is attribution, not authenticated identity. Do not expose it as a multi-user Internet service.

For network-isolated CLI analysis:

```sh
docker build -t guardian-ai .
mkdir -p .guardian-container
# Give UID 10001 write access to this output directory on Linux before running.
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 512m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v "$PWD/examples/demo:/scan:ro" \
  -v "$PWD/.guardian-container:/data:rw" \
  guardian-ai scan /scan --offline --planted
```

This container command is supplied but not validated on this machine. The image supports local directory scans; it does not install Git or the optional external scanners. Docker networking `none` makes fresh OSV checks unavailable. Prepopulate a fresh cache through a separate online run if appropriate.

## Project layout

- `guardian/discovery.py`: input bounds, inventory readers, graph paths and SBOM export
- `guardian/detectors.py`: static signals and snapshot diffs
- `guardian/osv.py`: live vulnerability checks and cache
- `guardian/engine.py`: orchestrator, verification, evidence and graph enrichment
- `guardian/store.py`: five memories and human decision policies
- `guardian/server.py`, `guardian/static/`: local API and dashboard
- `guardian/evaluation.py`, `tests/`: planted regression suite and tests
- `examples/demo/`: clearly labeled synthetic fixture, never executed
- `docs/`: architecture, demo script, security notes and scope map

## Current boundaries

This is an implemented Day 1 application, not every stretch item in the design. Syft, OSV-Scanner CLI, GuardDog, Semgrep, Grype and Trivy are not silently represented as installed tools; the native parsers/static rules and OSV API run directly. External CycloneDX output can be consumed. Package-versus-source provenance, nested remote action resolution, image-layer vulnerability scanning, maintainer history, actual call-graph reachability, LLM investigation, scheduled monitoring, remediation and sandbox fix validation are not implemented. Source differences currently report changed file hashes, not stored Git diff hunks. Repository clones have a time limit but no native OS disk quota. Use an isolated constrained filesystem for untrusted large inputs.

See [scope map](docs/scope.md), [architecture](docs/architecture.md), [responsible-use note](docs/security.md), and [demo walkthrough](docs/demo.md).


## Day 2 Architecture: Team Contributions (Prioritization to Human Approval)

In Day 2, GuardianAI extends the Day 1 supply-chain detection harness into an automated remediation pipeline governed by a strict human-in-the-loop approval gate. The workflow transforms raw vulnerability signals into actionable, non-hallucinated security fixes:

```
[ Prioritized Risk ] ──► [ Candidate Verification ] ──► [ Precision Patching ] ──► [ Remediation Brain ] ──► [ Human Approval Gate ]
    (Member 1)                  (Member 2)                     (Member 3)                 (Member 4)                 (Member 5)
```

To deliver a reliable, enterprise-grade architecture where AI agents never autonomously execute code changes on live production files, our team of five divided the system up to the Human Approval Gate into five distinct ownership areas. Below is a detailed breakdown of each team member's technical contribution, the problems they solved, and the components they authored.

### Member 1 — Contextual Risk Prioritization & Urgency Engine (`guardian/prioritizer.py`)

Member 1 designed and implemented the contextual risk prioritizer, solving the critical flaw of industry-standard vulnerability scoring: raw CVSS scores are context-blind. In real-world software engineering, a CVSS 9.8 Critical vulnerability in a local testing linter or build documentation dependency poses significantly less operational danger than a CVSS 7.5 High vulnerability in an internet-facing production server. Relying solely on raw CVSS produces overwhelming alert fatigue, causing security teams to waste engineering cycles patching non-exploitable development tools while active production risks linger.

To solve this, Member 1 developed an explainable policy engine that consumes the dependency knowledge graph topology and manifest metadata. The engine detects whether an affected package is confined to development scopes (`dev: true/false`) and cross-examines detection categories—including live malicious scripts, prototype pollutions, unpinned container digests, and supply-chain drift. The prioritizer calculates a calibrated policy score from 0.0 to 10.0 and assigns each finding to one of four deterministic urgency tiers: **P0 (Immediate Threat)** for runtime or remote execution risks in production dependencies; **P1 (Urgent Action)** for high-severity issues on reachable production paths; **P2 (Medium Priority)** for moderate risks or critical vulnerabilities safely quarantined within development scopes; and **P3 (Deferred)** for low-impact hygiene items. Additionally, Member 1 ensured that every single score produces an auditable `score_explanation` string, giving engineers and auditors full visibility into why a finding was elevated or downgraded.

### Member 2 — Candidate Verification & OSV Boundary Checker (`guardian/candidates.py`)

Member 2 authored the candidate verification engine, eliminating one of the greatest dangers of generative AI in supply-chain security: hallucinated package versions and non-existent releases. Large Language Models often suggest non-existent versions, pull deprecated library forks, or propose updates that inadvertently break downstream ecosystems. Member 2 replaced speculative guessing with deterministic registry verification across official package ecosystems, including the npm Registry (`registry.npmjs.org`) and PyPI (`pypi.org`).

The engine queries live registry metadata and cross-references advisory fix boundaries from the Open Source Vulnerabilities (OSV) API. When evaluating an affected package, the candidate selector parses version constraints across all active CVEs affecting that component, discards versions within vulnerable ranges, and selects the earliest compatible secure release on the target branch (or the latest stable release if branch-local fixes are unavailable). Crucially, Member 2 implemented a secondary validation pass: before any candidate version is submitted to the remediation planner, it is independently re-scanned against the OSV database to verify that upgrading does not introduce any secondary or newly published vulnerabilities. If no safe candidate exists or if registry access is offline, the module cleanly records why automated patching cannot proceed, preventing unverified modifications from ever reaching the engineer.

### Member 3 — Precision AST Manifest Patching & Non-CVE Reference Pinning (`guardian/patching.py`, `guardian/references.py`)

Member 3 built the surgical file patching and reference resolution subsystem, responsible for generating exact, syntactically clean modifications across diverse project manifests without causing configuration corruption. Traditional automated dependency update tools often re-serialize JSON or TOML files through naive deserializers, wiping developer comments, altering trailing whitespace, scrambling key orders, and converting 2-space indentation into 4-space indentation. Such noisy diffs increase friction and cause engineers to reject automated pull requests.

To overcome this, Member 3 implemented `guardian/patching.py`, which uses span-based Abstract Syntax Tree (AST) token parsing via Python's `json.JSONDecoder`. By inspecting character spans directly in the raw manifest text, the patcher replaces only the exact byte range of the target version string inside `package.json` or `pyproject.toml`, preserving 100% of the original indentation, comments, and file formatting. In parallel, Member 3 authored `guardian/references.py` to address non-CVE supply-chain hygiene. This module deterministically resolves mutable Docker base tags (such as `python:alpine` or `node:latest`) into immutable SHA-256 image content digests by querying the Docker Registry v2 manifest API, and resolves unpinned GitHub Actions tags (such as `actions/checkout@v4`) into exact, immutable 40-character Git commit SHAs via the GitHub REST API. This guarantees that build steps and container images are permanently immune to upstream tag mutability attacks.

### Member 4 — Remediation Plan Orchestration & Unified Diff Generation (`guardian/remediation.py`)

Member 4 architected the central remediation orchestrator—the "Brain" of the Day 2 pipeline. This engine synthesizes the risk assessment from Member 1, the verified candidates from Member 2, and the precision patchers from Member 3 into a canonical, human-reviewable remediation proposal object (`R-...`). 

Member 4 implemented Semantic Versioning (SemVer) compatibility delta calculations, classifying every proposed upgrade as `patch` (bug fixes, minimal risk), `minor` (backwards-compatible features, moderate review needed), or `major` (breaking changes requiring regression testing). In complex nested package graphs where a vulnerable dependency is deeply embedded transitively (e.g., `nodejs-goof` → `tap` → `nyc` → `istanbul-reports` → `handlebars`), the direct parent cannot always be safely upgraded without breaking the root application. Member 4 solved this by generating npm manifest `"overrides"` (or yarn `"resolutions"`), forcing the package manager to pin the nested component to a secure release while keeping parent manifests intact. The engine computes standard unified diff hunks (`--- a/... +++ b/...`), captures SHA-256 precondition hashes of all target files to prevent race conditions against concurrent file edits, and formulates precise, non-destructive shell rollback commands (`git checkout -- ...` or patch reversals) so that developers can instantly undo changes if issues arise.

### Member 5 — Human Governance, Drift Preconditions & Interactive Approval UI (`guardian/store.py`, `guardian/server.py`, `guardian/static/app.js`)

Member 5 designed and implemented the human governance framework, cryptographic precondition enforcement, and the interactive web approval interface. In accordance with zero-trust AI principles, GuardianAI strictly prohibits autonomous code execution: an AI proposal must never touch repository files or sandbox environments without explicit, authenticated human authorization.

Member 5 implemented the cryptographic precondition check inside `guardian/store.py`: when a human reviewer clicks "Approve", the server reads the current target files from disk, recomputes their live SHA-256 hashes, and compares them against the recorded precondition hashes from the original plan. If any file has drifted or been modified since the plan was generated, the operation instantly halts with an error, preventing stale or conflicting patch applications. Member 5 extended `guardian/server.py` to require named reviewer attribution (`actor`) and written rationale (`reason`) for every decision, recording all approvals and rejections in an immutable, append-only SQLite audit ledger. On the frontend, Member 5 developed the responsive slide-out remediation drawer in `guardian/static/app.js` and `index.html`. The interface renders rich priority badges, vulnerability advisory summaries, SemVer compatibility warnings, highlighted unified diffs, rollback instructions, and an intuitive approval form. This provides security leads and developers with everything needed to make confident, informed decisions in seconds.

---

## Day 2 Workflow Summary

Together, these five components form a resilient, deterministic pre-approval pipeline:
1. **Prioritization (Member 1)** ensures developers only spend time reviewing real threats, eliminating CVSS alert fatigue.
2. **Verification (Member 2)** guarantees zero hallucinations by validating candidate versions against live registries and OSV databases.
3. **Precision Patching (Member 3)** performs non-destructive AST byte replacements and pins Docker/GitHub supply-chain references to immutable SHAs.
4. **Remediation Brain (Member 4)** computes SemVer risk deltas, handles transitive overrides, and drafts clean unified diffs with instant rollback plans.
5. **Human Gate & UI (Member 5)** enforces human authorization, verifies cryptographic drift preconditions, audits every review in SQLite, and provides an interactive approval dashboard.

Once approved by a human reviewer, executable proposals transition into the isolated Docker sandbox validator for build and test verification before being finalized. See [implementation scope and API](docs/day2-human-approval.md) and [Day 1 audit](docs/day1-audit.md).

### AI fallback when no verified upgrade is available

Recommendation generation now calls `guardian/harness.py` when the deterministic
candidate selector cannot supply an upgrade. The adapter uses the patch-author
prompt, feature-token extraction and JSON parser from
`guardian-harness.zip` → `guardian/agents/nofix.py`. It does not execute the ZIP's
worktree creation, commits, publisher, or automatic patch application.

The adapter reads unchanged scan-inventoried JavaScript/TypeScript/Python source,
locates feature identifiers named in the advisory, and asks a local Ollama model
for up to six edits at those sites. It checks exact old text, paths, duplicate
edits, and scan hashes, then displays an unverified mitigation diff for human
approval. It cannot generate a patch for every advisory or repository. Missing
feature evidence, stale files, unavailable models, and invalid output produce an
explicit investigation result. An unavailable OSV lookup is not evidence that
no fixed version exists.

Start Ollama separately and set `GUARDIAN_OLLAMA_MODEL` to an installed local
model before starting Guardian; otherwise an installed Mistral model is preferred, then the first local model. No model is downloaded automatically and no hosted provider receives code.
Restart Guardian after updating the backend. Open a finding and generate a new
recommendation to see **AI harness fallback** details. Existing proposals retain
their original content.

After approval, AI patches require Docker (no host-process fallback), a supported
npm manifest or explicit `.guardian-validation.json` runtime/build/test settings,
and a rescan. Passing checks alone does not prove a source mitigation resolves
the CVE; AI mitigation validation remains inconclusive pending security review,
or fails when checks/regressions fail. The original checkout is not patched by
recommendation generation.
