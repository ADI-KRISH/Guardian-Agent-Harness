# GuardianAI: Agentic Security Workflow Architecture

GuardianAI operates as an **orchestrated multi-agent supply chain intelligence system**. It blends **deterministic specialist agents** with an **isolated, read-only AI investigation agent** and a strict **human-in-the-loop verification gate**.

---

## 1. High-Level Multi-Agent Architecture

```mermaid
flowchart TD
    User([User / Web UI / CI]) -->|Scan Request| Orchestrator[01. Orchestrator Agent]
    
    subgraph SelfCheck [Safety & Integrity Gate]
        Orchestrator --> Canary[Self-Check & Canary Gate]
        Canary -->|Verified| Prep[Snapshot Isolation]
    end

    subgraph Preparation [Phase 1: Inventory & Resolution]
        Prep --> Resolver[02. Resolver Agent\nIsolated npm sandbox, scripts disabled]
        Resolver --> Discovery[03. Discovery Agent\nLockfiles, manifests, SBOM parsing]
        Discovery --> Baseline[04. Baseline Diff Agent\nGit HEAD^ or approved baseline]
    end

    subgraph ParallelSpecialists [Phase 2: Parallel Specialist Analysis]
        Discovery --> Pool[Parallel Execution Pool]
        Pool --> VulnAgent[05. Vulnerability Agent\nOSV exact-version queries & cache]
        Pool --> BackdoorAgent[06. Backdoor & CI Agent\nAST/regex static flows & workflow audit]
        Pool --> ContainerAgent[07. Container Agent\nDockerfile, Compose & Trivy image audit]
    end

    subgraph VerificationMemory [Phase 3: Verification & Memory]
        VulnAgent & BackdoorAgent & ContainerAgent & Baseline --> Verifier[08. Verifier Agent\nFact & line-bound validator]
        Verifier --> Learning[09. Learning & Memory Agent\nScoped, expiring lessons & suppression]
    end

    subgraph ReasoningReporting [Phase 4: Reasoning & Synthesis]
        Learning --> AIInvestigator[10. AI Investigator Agent\nLocal Ollama LLM, read-only inference]
        AIInvestigator --> EvidenceAgent[11. Evidence & Knowledge Graph Agent\nCycloneDX 1.5 SBOM, Cytoscape Graph]
    end

    subgraph HumanControl [Phase 5: Human in the Loop]
        EvidenceAgent --> Dashboard([Interactive Cytoscape Graph & UI])
        Dashboard --> HumanReview[Human Reviewer]
        HumanReview -->|Promote Baseline / Approve Lesson / Review Finding| AuditTrail[(Append-Only Audit Ledger)]
    end
```

---

## 2. Detailed Agent Roles & Responsibilities

| # | Agent Name | Module | Responsibility & Guarantees |
|---|---|---|---|
| **01** | **Orchestrator** | `engine.py` | Validates input bounds, sandboxes Git repositories (`core.hooksPath=/dev/null`, depth limits), schedules pipeline phases, and runs local canary tests. |
| **02** | **Resolver Agent** | `resolver.py` | Handles repos lacking committed lockfiles (e.g. OWASP Juice Shop). Resolves dependency trees in a disposable directory with `--ignore-scripts`, registry-only pinning, and marks results as *generated*. |
| **03** | **Discovery Agent** | `discovery.py`, `formats.py` | Parses lockfiles across Dart, npm, PyPI, Go, Cargo, Maven, Gradle, NuGet. Computes package coordinates (pURL), captures direct vs transitive relationships, and extracts exact lines. |
| **04** | **Baseline Diff Agent** | `detectors.py`, `history.py` | Compares current snapshot with `HEAD^` or a human-approved baseline. Detects added/removed/updated packages, file modifications, and critical checksum mismatches. |
| **05** | **Vulnerability Agent** | `osv.py` | Performs batch exact-version lookups against OSV.dev (CVE, GHSA). Caches responses in SQLite for 24h, extracts fixed boundaries, and scores CVSS. |
| **06** | **Backdoor & CI Agent** | `detectors.py`, `flow.py` | Static detectors for malicious source patterns: `curl \| sh`, unpinned GitHub Actions, `pull_request_target`, install hooks (`postinstall`), bidi overrides, obfuscated base64 execution, and bounded sensitive data exfiltration to outbound network sinks. |
| **07** | **Container Agent** | `containers.py` | Evaluates Dockerfile base images (floating tags vs digest pinning), privileged containers, root execution, socket mounts (`docker.sock`), and triggers optional local Trivy scans for OS layers. |
| **08** | **Verifier Agent** | `verifier.py` | **Defense against hallucinations and false positives.** Rechecks every finding against the immutable snapshot files, verifies line numbers, confirms exact package identities, and calculates confidence ratings. Rejects invalid signals. |
| **09** | **Learning & Memory Agent** | `store.py` | Applies human-approved, scoped, expiring suppression rules for confirmed false positives. **Enforces policy guardrails:** protected rules (e.g., integrity mismatch, secret exfiltration) can never be suppressed. |
| **10** | **AI Investigator Agent** | `ai.py` | Uses a local Ollama instance (Mistral/Llama) with strict boundaries: treated as untrusted data input, produces read-only hypotheses and recommended checks without the authority to alter severities, suppress findings, or approve baselines. |
| **11** | **Evidence & Graph Agent** | `engine.py`, `app.js` | Synthesizes findings into a CycloneDX 1.5 SBOM, generates BFS dependency paths from `app` to vulnerable nodes, builds the Cytoscape knowledge graph, and commits every decision to an append-only audit trail. |

---

## 3. Strict Determinism & Agent Safety Guardrails

GuardianAI adheres to five key design principles to prevent agentic hallucination or supply-chain execution attacks:

```mermaid
graph LR
    A[Untrusted Target Repo] -->|Read-Only Ingestion| B[No Code Execution]
    B -->|Lifecycle Scripts Disabled| C[Isolated Temporary Sandbox]
    C -->|Re-Verified by Deterministic Rules| D[AI Model = Read-Only Analyst]
    D -->|Cannot Alter Findings/Severities| E[Human-Gated Approvals]
```

1. **Zero Execution of Target Code**:
   - `npm install --package-lock-only --ignore-scripts`
   - Git clones run with `core.hooksPath=/dev/null` and `--no-recurse-submodules`.
2. **AI Inference is Firewalled from Verified Evidence**:
   - The LLM receives finding summaries as untrusted data in an isolated prompt with strict negative instructions.
   - LLM responses cannot change CVSS scores, suppress findings, or invent package dependencies.
3. **Protected Guardrails in Learning Memory**:
   - Lessons allow suppressing false alarms after human review, but critical signals (integrity mismatches, raw token exfiltration) cannot be suppressed by any lesson.
4. **Independent Verifier Step**:
   - Findings produced by heuristic rules must pass the Verifier Agent, ensuring the referenced files, lines, and package identities actually exist in the raw repository snapshot.
5. **Full Traceability**:
   - Every single agent transition, verification rejection, lesson suppression, and human review is permanently stamped into the SQLite audit ledger with timestamps and cryptographic IDs.
