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
