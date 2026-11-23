# GuardianAI 2.0: Architecture, Risk Detection & Technical Guide

GuardianAI is an **agentic software supply-chain intelligence and assurance platform**. It discovers software components, constructs verified dependency knowledge graphs, detects vulnerabilities and malicious backdoor patterns, correlates baseline changes, and provides human-governed decision workflows with full auditability.

---

## 1. Executive Overview & Problem Solved

Software supply chain attacks operate across multiple dimensions:
- **Known CVEs in transitive dependencies** hidden deep within dependency trees.
- **Dependency confusion and typosquatting** in manifests.
- **Unpinned or floating CI/CD workflows and actions** vulnerable to upstream hijacking.
- **Malicious lifecycle scripts** (`preinstall`, `postinstall`) executing payload code.
- **Dynamic exfiltration vectors** leaking build secrets / credentials to network endpoints.
- **Silent dependency changes** where package versions remain identical but published package integrity hashes differ.

GuardianAI addresses these threats by providing **deterministic, multi-agent analysis with verifiable evidence chains**, keeping human security analysts firmly in control.

---

## 2. System Architecture

GuardianAI operates in 5 orchestrated phases:

```
┌────────────────────────────────────────────────────────────────────────┐
│                          0. Target Snapshot                            │
│  Git clone (hooks disabled) or local path read-only snapshot traversal │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     1. Resolution & Discovery                          │
│  • Resolver Agent: Isolated, script-free synthesis for lockless repos  │
│  • Discovery Agent: Lockfiles, manifests, CycloneDX 1.5 SBOM parser    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   2. Parallel Specialist Analysis                      │
│  ┌────────────────────┬────────────────────┬────────────────────────┐  │
│  │ Vulnerability      │ Backdoor & CI      │ Container Agent        │  │
│  │ Agent (OSV exact)  │ Agent (Static AST) │ (Dockerfile, Trivy)    │  │
│  └────────────────────┴────────────────────┴────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Baseline Diff Agent (HEAD^ or Human-Approved Baseline)           │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   3. Verification & Memory Gating                      │
│  • Verifier Agent: Evidence re-check (line bounds, exact identities)   │
│  • Learning Agent: Human-approved expiring lessons (suppression guards)│
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   4. AI Investigation & Synthesis                      │
│  • Local Ollama Agent: Read-only hypothesis generation (no trust write)│
│  • Cytoscape Knowledge Graph & CycloneDX SBOM synthesis                │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       5. Human Control & UI                            │
│  • Interactive Visual Graph (Risk, Direct, Ecosystem subgraphs)        │
│  • Print-Ready PDF Executive Report & CycloneDX SBOM JSON exports      │
│  • Persistent Audit Trail & Human Decision Ledger                      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. How Risks Are Identified

GuardianAI uses specialized detection agents that look for distinct classes of security risks:

### A. Known Vulnerabilities (CVE / GHSA)
- **Agent**: `Vulnerability Agent` (`guardian/osv.py`)
- **Methodology**: Performs exact-version component queries against the open OSV.dev database (supporting npm, PyPI, Maven, Go, Cargo, NuGet, Pub).
- **Transitive Traceability**: For any matched vulnerability in a transitive package, a Breadth-First Search (BFS) graph traversal traces the exact chain from the root application (`app -> package-a -> package-b -> vulnerable-dep`).
- **Performance**: High-speed batch lookups backed by a local 24-hour SQLite query cache.

### B. Supply Chain Anomaly & Backdoor Patterns
- **Agent**: `Backdoor / CI Agent` (`guardian/detectors.py`, `guardian/flow.py`)
- **Key Detection Rules**:
  1. **Secret Exfiltration (`secret-exfiltration`)**: Identifies actual flow of sensitive variables (`TOKEN`, `SECRET`, `PASSWORD`, `API_KEY`, `CREDENTIAL`, or full env serialization) into outbound network sinks (`fetch()`, `axios`, `http.request`, `sendBeacon`). Ordinary reads of `PORT`, `NODE_ENV`, or `OSTYPE` are excluded to eliminate false positives.
  2. **Script Download and Execution (`download-execute`)**: Flags curl/wget piped directly to shells (`curl ... | sh`, `wget ... | bash`) in workflows and source files.
  3. **Unpinned GitHub Actions (`unpinned-action`)**: Flags third-party GitHub Actions referenced by floating tags or branches (e.g., `@v3`) rather than full 40-character commit SHAs.
  4. **Privileged Workflows (`privileged-workflow`)**: Highlights dangerous triggers like `pull_request_target` or `permissions: write-all` that execute attacker-supplied PR code in elevated contexts.
  5. **Malicious Lifecycle Scripts (`install-script`)**: Detects `preinstall`, `install`, and `postinstall` hooks in `package.json` and lockfiles.
  6. **Obfuscated Execution (`obfuscated-execution`)**: Detects runtime decoding paired with dynamic evaluation (e.g. `base64` / `b64decode` / `atob` -> `eval()` / `exec()`).
  7. **Bidirectional Source Characters (`bidi-source`)**: Detects invisible Trojan Source characters (Unicode `\u202A`–`\u202E`, `\u2066`–`\u2069`) capable of altering compiler interpretation without visual cues.
  8. **Typosquatting (`typosquat`)**: Levenshtein heuristic distance matching package names against common popular packages.

### C. Container & Infrastructure Risks
- **Agent**: `Container Agent` (`guardian/containers.py`)
- **Detection Rules**:
  - **Floating Container Base Images (`floating-image`)**: Flags `FROM` directives in `Dockerfile` and `image:` declarations in Compose missing `@sha256:` immutable digests.
  - **Privileged Containers (`privileged-container`)**: Flags `privileged: true` in Compose files.
  - **Docker Socket Exposure (`docker-socket`)**: Flags mounts of `/var/run/docker.sock` giving host-level root control.
  - **Host Networking (`host-network`)**: Flags `network_mode: host`.
  - **Image Layer Vulnerabilities**: Integrates with local Trivy to scan remote/local image layers for OS package CVEs when requested.

### D. Silent Baseline & Integrity Changes
- **Agent**: `Baseline Diff Agent` (`guardian/detectors.py:changes`)
- **Methodology**: Compares current project state against a human-promoted baseline or the parent Git commit (`HEAD^`).
- **Integrity Drift (`integrity-change`)**: Flags packages where the version is identical to the baseline, but the package cryptographic content hash differs—a classic sign of compromised registries or tampering.
- **Drift Tracking**: Catalogs all added, removed, and updated dependencies and source files.

---

## 4. Multi-Language & Lockfile Support

GuardianAI supports multi-language projects via deterministic lockfile readers without executing build code:

| Ecosystem | Manifests & Lockfiles | Edge Fidelity |
|---|---|---|
| **Node.js** | `package-lock.json`, `npm-shrinkwrap.json` | Exact component + transitive edges |
| **Yarn** | `yarn.lock` (Classic & Berry YAML) | Exact component + transitive edges |
| **pnpm** | `pnpm-lock.yaml` (v5, v6, v9) | Exact component + transitive edges |
| **Python** | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements.txt`, `pyproject.toml` | Exact packages & resolved constraints |
| **Go** | `go.mod`, `go.sum` | Direct/indirect module inventory with checksums |
| **Rust** | `Cargo.lock` | Full crate inventory with transitive edges |
| **Java** | `pom.xml`, `build.gradle`, `gradle.lockfile` | Manifest declarations & locked coordinates |
| **.NET** | `packages.lock.json`, `.csproj` | Exact NuGet packages with content hashes |
| **Flutter / Dart** | `pubspec.lock`, `pubspec.yaml` | Exact pub.dev packages with sha256 hashes |
| **Containers** | `Dockerfile`, `docker-compose.yml` | Base images, configurations, socket bindings |
| **Universal** | CycloneDX 1.5 JSON SBOMs | Full standard component & dependency mapping |

> **Automated Lockfile Synthesis**: For repositories without committed lockfiles (like OWASP Juice Shop), the Resolver Agent runs `npm install --package-lock-only --ignore-scripts` inside an isolated temporary sandbox to generate an exact resolution without executing any third-party scripts.

---

## 5. Defense-in-Depth & Agentic Safety Guardrails

GuardianAI strictly isolates untrusted input from execution and analysis:

1. **Zero Execution Policy**: Target code is never executed. Lifecycle scripts, git hooks, and build scripts are disabled during cloning and resolution.
2. **Deterministic Verification Gate**: The `Verifier Agent` validates all static signals before they reach the report. If a finding cites an invalid line number or non-existent file, it is discarded.
3. **AI Inference Firewall**: The optional local Ollama LLM is isolated. Its responses are classified as `inferred`, clearly marked as non-factual hypotheses, and cannot modify trust ratings, suppress findings, or approve baselines.
4. **Protected Rule Guardrails**: Human reviewers can suppress repeated false positives using expiring, scoped lessons. However, protected core rules (e.g. `integrity-change`, `secret-exfiltration`) are blocked from suppression by policy.
5. **Tamper-Evident Audit Log**: Every stage transition, detector hit, verification pass, and human approval is immutably logged into an append-only SQLite database.

---

## 6. Visualization & Reporting

- **Interactive Cytoscape.js Graph**:
  - **Risk-Focus Mode**: Highlighting critical/high-risk chains while pruning clutter on massive enterprise projects.
  - **Direct Dependencies Mode**: Quick visibility into root project imports.
  - **Ecosystem Grouping**: Color-coded categorization by language platform.
  - **Interactive Subgraphs**: Click any node to open a 2-hop focused neighbourhood view.
- **Export Capabilities**:
  - **Print-Ready Executive PDF Report**: Single-click PDF generation with executive summaries, SBOM summaries, finding details, and risk heatmaps.
  - **Standard CycloneDX 1.5 SBOM**: Downloadable JSON specification compatible with enterprise supply-chain tooling.

---

## 7. Quickstart & Usage

### Setup
```bash
# Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Launch Web Console
```bash
python3 -m guardian
# Access UI at http://127.0.0.1:8787
```

### CLI Scan
```bash
# Scan a local folder
guardian-scan /path/to/my-repo

# Scan a public GitHub repository
guardian-scan https://github.com/OWASP/juice-shop

# Offline mode using cached advisories
guardian-scan /path/to/my-repo --offline
```

