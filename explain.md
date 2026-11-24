# GuardianAI: Deep Technical Architecture & Operational Guide

GuardianAI is an **agentic software supply chain intelligence platform**. It analyzes source code, manifests, lockfiles, CI/CD pipelines, and container configurations to construct an immutable **Software Bill of Materials (SBOM)**, build an interactive **dependency knowledge graph**, identify **known vulnerabilities (CVEs)** and **malicious supply-chain anomalies**, and establish **tamper-evident audit trails**.

This document explains the full end-to-end mechanics of how GuardianAI operates under the hood.

---

## Table of Contents
1. [End-to-End Execution Flow](#1-end-to-end-execution-flow)
2. [How Dependencies Are Discovered](#2-how-dependencies-are-discovered)
3. [Handling Repositories Without Lockfiles (Isolated Resolution)](#3-handling-repositories-without-lockfiles-isolated-resolution)
4. [How the Knowledge Graph Is Constructed](#4-how-the-knowledge-graph-is-constructed)
5. [How Vulnerabilities & Anomalies Are Found](#5-how-vulnerabilities--anomalies-are-found)
6. [How Risks Are Ranked & Scored](#6-how-risks-are-ranked--scored)
7. [The Verification & Memory Safety Net](#7-the-verification--memory-safety-net)
8. [Interactive Cytoscape.js Graph Engine](#8-interactive-cytoscapejs-graph-engine)

---

## 1. End-to-End Execution Flow

When a scan is initiated (via Web UI or CLI `python3 -m guardian scan <target>`), the engine executes a strict 5-stage deterministic pipeline:

```
[Target Ingestion]
       │
       ▼
[Stage 1: Pre-flight & Isolation]
 • Target checkout with hooks disabled (core.hooksPath=/dev/null)
 • Canary self-check (verifies detector integrity before processing)
       │
       ▼
[Stage 2: Resolution & Discovery]
 • Resolver Agent: Isolated, script-free lockfile synthesis if lockfiles are missing
 • Discovery Agent: Reads tree, extracts exact file lines, parses manifests/lockfiles
 • Baseline Agent: Pulls Git HEAD^ or promoted baseline for differential diff
       │
       ▼
[Stage 3: Parallel Specialist Analysis]
 ├── Vulnerability Agent: Queries OSV.dev in batch for exact version CVE/GHSA matches
 ├── Backdoor & CI Agent: AST & regex flow scanning for malicious patterns
 └── Container Agent: Audits Dockerfiles, Compose files, and optional Trivy image scans
       │
       ▼
[Stage 4: Verification & Memory Gating]
 • Verifier Agent: Validates line bounds, file existence, and component identities
 • Learning Agent: Applies human-approved suppression lessons (guarded against bypass)
 • AI Investigator: Optional local Ollama model generates read-only hypotheses
       │
       ▼
[Stage 5: Synthesis & Reporting]
 • Generates CycloneDX 1.5 JSON SBOM
 • Computes BFS dependency paths from root to affected packages
 • Constructs Cytoscape Knowledge Graph & generates 1-click PDF reports
 • Commits all decisions to SQLite append-only audit ledger
```

---

## 2. How Dependencies Are Discovered

The **Discovery Agent** (`guardian/discovery.py` & `guardian/formats.py`) traverses the repository up to a strict limit of 12,000 files and 64 MB total memory budget. It reads and parses dependency files across all major programming ecosystems without executing target code:

| Ecosystem | Files Parsed | How Dependencies & Versions Are Extracted |
|---|---|---|
| **Node.js (npm)** | `package-lock.json`, `npm-shrinkwrap.json` | Reads `packages` (v2/v3 lockfiles). Identifies package version, integrity hash (`sha512`), `hasInstallScript`, and maps nested `node_modules/...` hierarchy. |
| **Yarn** | `yarn.lock` | Parses classic indentation-based format or Berry (v2+) YAML. Resolves selector strings (`react@^18.0.0` -> exact `18.2.0`). |
| **pnpm** | `pnpm-lock.yaml` | Reads `importers` (roots) and `snapshots`/`packages`. Resolves hard links and dependency graph without filesystem extraction. |
| **Python** | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements.txt`, `pyproject.toml` | Parses TOML/text without running `setup.py`. Extracts exact package names (normalized with PEP 503 rules) and hashes. |
| **Go** | `go.mod`, `go.sum` | Parses module requirement blocks and lines marked `// indirect`. Correlates cryptographic hashes from `go.sum`. |
| **Rust** | `Cargo.lock` | Parses TOML package tables. Correlates crate names, versions, and checksums. |
| **Java / JVM** | `pom.xml`, `build.gradle`, `gradle.lockfile` | Static XML/regex parsing for coordinates (`groupId:artifactId:version`). Never runs Gradle daemons. |
| **.NET** | `packages.lock.json`, `.csproj` | Parses NuGet lockfiles for direct/transitive packages and `contentHash`. |
| **Flutter / Dart**| `pubspec.lock`, `pubspec.yaml` | Parses hosted pub.dev packages, checking sha256 integrity. |
| **Generic / Any** | CycloneDX 1.5 JSON | Standard SBOM parser linking component `purl`s and `dependsOn` arrays. |

### Component Identity (pURL)
Every discovered component is assigned a standardized **Package URL (pURL)**:
```
pkg:npm/lodash@4.17.21
pkg:pypi/requests@2.31.0
pkg:golang/github.com/gin-gonic/gin@v1.9.1
pkg:cargo/serde@1.0.193
```
This guarantees unique, universally identifiable keys across ecosystems.

---

## 3. Handling Repositories Without Lockfiles (Isolated Resolution)

Many real-world repositories (such as **OWASP Juice Shop**) commit only `package.json` with open version ranges (e.g. `"express": "^4.17.1"`), omitting a lockfile. 

Standard static scanners typically fail here—they either skip ranges entirely (leaving 95%+ of dependencies unchecked) or make naive assumptions.

**GuardianAI's Resolver Agent (`guardian/resolver.py`) solves this:**
1. **Isolated Disposable Sandbox**: Creates a clean, temporary directory outside the repository.
2. **Sanitized Manifest Extraction**: Copies only safe registry dependency names and ranges into an isolated `package.json`. Strips out custom git URLs, local paths, and root scripts.
3. **Lockfile Generation Without Execution**:
   ```bash
   npm install --package-lock-only --ignore-scripts --no-audit --no-fund --legacy-peer-deps
   ```
   - `--package-lock-only`: Only queries registry metadata to resolve transitive versions; does **not** download or unpack tarballs.
   - `--ignore-scripts`: Completely forbids execution of `preinstall`, `install`, or `postinstall` scripts.
   - Root `node_modules/` is never populated.
4. **Transparent Labeling**: The resulting lockfile is saved in the Guardian resolution cache, and every package derived from it is flagged with `generated: true` so analysts know it was resolved from current registry state rather than a committed developer snapshot.

---

## 4. How the Knowledge Graph Is Constructed

The knowledge graph is a directed multigraph representing entities and their interactions:

### Graph Entities (Nodes)
- **Application Node (`app`)**: The root project repository.
- **Package Nodes (`pkg:...#location`)**: Libraries identified by pURL, ecosystem, version, directness (`direct: true/false`), and integrity.
- **Finding Nodes (`G-<hash>`)**: Security alerts (vulnerabilities, backdoors, misconfigurations).
- **File Nodes (`file:<path>`)**: Source files that provide supporting evidence.

### Graph Relationships (Edges)
- `app` ──`declares` / `depends_on`──> `package`
- `package-A` ──`depends_on`──> `package-B` (transitive relationship)
- `package` ──`affected_by`──> `finding`
- `finding` ──`evidenced_by`──> `file`

### BFS Dependency Path Tracing
For every finding on a transitive dependency, the engine runs a **Breadth-First Search (BFS)** traversal starting from `app` following `depends_on` edges:
```
app ──> express@4.17.1 ──> cookie-parser@1.4.5 ──> cookie@0.4.0 (Vulnerable)
```
This shows engineers the exact dependency chain that pulled the vulnerable package into their application.

---

## 5. How Vulnerabilities & Anomalies Are Found

GuardianAI runs three specialist agents in parallel:

### A. Vulnerability Agent (`guardian/osv.py`)
- **Database**: OSV.dev (Open Source Vulnerabilities), which aggregates CVE, GitHub Security Advisories (GHSA), RustSec, Go Vulnerability DB, and PyPA.
- **Exact-Version Queries**: Sends batches of exact package versions. For example:
  `{"package": {"name": "jsonwebtoken", "ecosystem": "npm"}, "version": "0.4.0"}`
- **Fixed Boundary Extraction**: Parses advisory version ranges (`fixed: "9.0.0"`) to display recommended upgrade boundaries.
- **Local SQLite Cache**: Responses are cached locally with a 24-hour TTL. Offline mode allows scanning using cached advisories without internet access.

### B. Backdoor & CI Agent (`guardian/detectors.py`, `guardian/flow.py`)
Deterministic rules detect suspicious supply chain signals:
1. **Secret Exfiltration (`secret-exfiltration`)**:
   - Uses localized AST and lexical dataflow matching.
   - Flags when sensitive variables (`TOKEN`, `SECRET`, `PASSWORD`, `API_KEY`, `CREDENTIAL`, or full env dumps) flow into outbound network calls (`fetch`, `axios`, `http.request`, `sendBeacon`).
   - Ordinary configuration reads (`PORT`, `NODE_ENV`, `OSTYPE`, `PATH`) are explicitly filtered to prevent false positives.
2. **Download & Execute (`download-execute`)**:
   - Detects `curl ... | sh` or `wget ... | bash` in source files and CI workflow `run:` steps.
3. **Privileged Workflows (`privileged-workflow`)**:
   - Detects GitHub Actions using `pull_request_target` (runs with repo secrets on external forks) or `permissions: write-all`.
4. **Unpinned Actions (`unpinned-action`)**:
   - Flags GitHub Actions pinned to mutable branches/tags (e.g. `@v3`) instead of immutable 40-character commit SHAs.
5. **Lifecycle Scripts (`install-script`)**:
   - Flags packages containing `preinstall`, `install`, or `postinstall` scripts that run arbitrary code on developer machines during install.
6. **Obfuscated Dynamic Execution (`obfuscated-execution`)**:
   - Flags `base64` / `b64decode` / `atob` paired with dynamic `eval()` or `exec()`.
7. **Trojan Source Bidi Characters (`bidi-source`)**:
   - Detects Unicode directional control characters (`\u202A` through `\u2069`) that alter compiler interpretation of source lines.
8. **Typosquatting (`typosquat`)**:
   - Flags package names that closely mimic popular packages (e.g. `reqeusts` vs `requests`) using Levenshtein distance matching.

### C. Container Agent (`guardian/containers.py`)
- **Floating Base Images (`floating-image`)**: Flags `FROM` directives in `Dockerfile` and `image:` lines in Compose that lack `@sha256:` immutable digests.
- **Dangerous Privileges**: Flags `privileged: true`, host networking (`network_mode: host`), or mounting the Docker control socket (`/var/run/docker.sock`).
- **OS Layer Scans**: Invokes local `trivy` in an isolated cache directory when `--scan-images` is requested.

---

## 6. How Risks Are Ranked & Scored

Every finding is assigned an objective numerical severity score based on its category:

### Base Severity Scores
| Severity | Score | Description |
|---|---|---|
| **Critical** | `9.5 / 10.0` | High-confidence exploitable CVEs with known exploits, silent package integrity tampering. |
| **High** | `8.0 / 10.0` | Backdoor signals (token exfiltration, download-and-execute), privileged CI workflows, high-severity CVEs. |
| **Medium** | `5.5 / 10.0` | Unpinned container base images, unpinned GitHub Actions, typosquatting heuristic alerts, medium CVEs. |
| **Low** | `2.5 / 10.0` | Newly added packages, unpinned dependencies, informational notes. |

### Confidence Tiers
GuardianAI explicitly separates **detection score** from **confidence rating**:
- **High Confidence**: Deterministically verified against immutable records (e.g., exact package version matches an advisory ID; or cryptographic hash mismatch between two snapshots).
- **Medium Confidence**: Static pattern match verified to exist at a specific line in the repository snapshot, but runtime exploitability is unknown.
- **Low Confidence**: Statistical or heuristic observations (e.g., name similarity in typosquatting) without corroborating malicious payload evidence.

### Sorting Order
The final report sorts findings with this prioritization key:
```python
findings.sort(key=lambda f: (f['suppressed'], -f['score'], f['id']))
```
Active (unsuppressed) Critical and High findings always float to the top; suppressed false alarms are pushed to the bottom.

---

## 7. The Verification & Memory Safety Net

To guarantee reliability, GuardianAI implements three protective safety layers:

### Layer 1: The Verifier Agent (`guardian/verifier.py`)
Before any finding is accepted into the ledger, the Verifier Agent independently validates it:
- Does the cited evidence file actually exist in the scan snapshot?
- Is the cited line number within the bounds of that file?
- Does the package identity in the OSV advisory match the exact inventory node?
If any check fails, the finding is **rejected and audited** as a hallucination/malformed signal.

### Layer 2: Scoped & Expiring Lessons (`guardian/store.py`)
When a human analyst reviews a finding as a "False Positive", the system creates a **Lesson**:
- **Scope**: Tied to a specific rule and file path.
- **Expiration**: Lessons automatically expire after a set duration (e.g. 90 days), forcing re-evaluation when code changes.
- **Protected Rules Bypass Guard**: Core rules such as `integrity-change` and `secret-exfiltration` **cannot be suppressed** by any lesson.

### Layer 3: The AI Reasoning Firewall (`guardian/ai.py`)
When local Ollama AI analysis is enabled:
- The AI runs in an isolated prompt with strict system instructions treating the evidence as untrusted data.
- The AI's output is strictly stored under `ai_inference[]` and marked as unverified commentary.
- **The AI cannot modify risk scores, cannot suppress findings, cannot approve baselines, and cannot invent evidence.**

---

## 8. Interactive Cytoscape.js Graph Engine

On large repositories (e.g., OWASP Juice Shop with 4,000+ packages and 8,000+ edges), rendering all nodes simultaneously creates an unreadable "hairball."

GuardianAI implements a **Smart View Subsetting Engine** (`guardian/static/app.js`):

### Smart View Modes
1. **🔴 Risk Focus Mode (Default)**:
   - Always keeps the root `app` node.
   - Extracts all nodes with **Critical** and **High** findings.
   - Pulls in the direct parent nodes of those risky packages to preserve dependency context.
   - Caps the display to the top 100-150 most critical nodes for instant clarity.
2. **📦 Direct Dependencies Mode**:
   - Shows only packages directly declared in the root project manifests plus any connected risky nodes.
3. **🗂 Ecosystem Mode**:
   - Samples packages evenly across all detected ecosystems (npm, PyPI, Go, etc.), prioritizing risky nodes within each ecosystem.

### Interactive Neighbourhood Exploration
Clicking any node in the graph opens a dedicated drawer with a **"Show 2-hop subgraph"** action:
- Dynamically extracts a focused 2-hop neighbourhood around that specific component.
- Allows engineers to trace immediate parents and children without visual noise.

### Dynamic Layout Engine
- **≤ 80 nodes**: CoSE (Compound Spring Embedder) force-directed physics layout with node repulsion.
- **80 – 200 nodes**: Relaxed CoSE layout with increased edge lengths.
- **200+ nodes**: Breadth-First tree layout rooted at `app` to maintain vertical hierarchical readability.

### Visual Cues
- **Critical Risk Nodes**: Red diamond shape with a glowing drop-shadow.
- **High Risk Nodes**: Orange circle with amber shadow.
- **Application Node**: Teal hexagon.
- **Ecosystem Color Rings**: Distinct colors for npm (orange), PyPI (blue), Maven (red), Go (cyan), Cargo (rust), NuGet (purple), and Dart (teal).
- **Hover Isolation**: Hovering over any node dims unrelated nodes to 12% opacity while highlighting immediate dependency paths.

---

## Summary

GuardianAI delivers a complete Day-1 and Day-2 software supply chain security solution:
- **Discovers** full dependency trees across all ecosystems.
- **Resolves** missing lockfiles safely in an isolated sandbox.
- **Constructs** CycloneDX 1.5 SBOMs and interactive Cytoscape knowledge graphs.
- **Detects** known CVEs and advanced supply-chain backdoor flows.
- **Verifies** every signal deterministically before presentation.
- **Empowers** human reviewers with auditable, expiring suppression controls and print-ready PDF reports.

