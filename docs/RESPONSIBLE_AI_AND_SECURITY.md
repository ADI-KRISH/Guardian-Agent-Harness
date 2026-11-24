# Responsible AI and security note

## 1. Where AI is used (and where it is not)

| Stage | AI? | What decides the outcome |
|---|---|---|
| Discover (inventory, SBOM, graph) | **No** | Lockfile / manifest parsing |
| Detect (CVEs, malware, typosquats, tampering, images, CI) | **No** | Advisory databases, npm registry, fixed rules |
| Analyze: risk score, priority, confidence | **No** | Explainable formula: severity/CVSS + exploitability + reachability + exposure. Every point is listed as a factor. |
| Analyze: plain-language explanation | **Optional AI** (Analyst) | Model explains the facts. It may *suggest* moving priority by at most one level. The suggestion is shown, never applied automatically. |
| Investigate one non-CVE risk | **Optional AI** (Investigator) | Verified facts are gathered deterministically. The model writes a hypothesis/verdict, stored separately and labelled "inference". |
| Remediation options | **No** | Registry data + semver + the lockfile's declared ranges |
| Executive summary in the final report | **Optional AI** (Reporter) | Model summarises numbered verified facts (S1, S2…). Every number, id and version it writes must appear in those facts, otherwise the deterministic summary is used. |
| Approval | **Human only** | Named person + written reason. Names starting with `guardian`, `ai`, `bot` are refused. |
| Validation (build, tests, rescan, SBOM diff) | **No** | Real build and test exit codes, rescan results |

AI is optional. With no model configured (`GUARDIAN_LLM=none`, the default without a key), every stage still works and explanations come from deterministic templates. The report shows which one produced each explanation.

Providers (auto-detected, see `guardian ai-check`):
- Anthropic Claude, Google Gemini (free key), Groq (free key), or any OpenAI-compatible endpoint.
- A **local Ollama model**, for teams that cannot send data off-premises.

With hosted providers, only the evidence JSON leaves the machine (package names, versions, advisory text, file names of importers). No source code or secrets are sent.

## 2. How hallucinations are controlled

1. **Grounded input only.** The model receives one finding as JSON: evidence items with ids (E1, E2… / F1, F2…), the dependency path, and the score factors. No other context.
2. **Strict output schema.** The answer must be one JSON object with fixed fields; anything else is rejected.
3. **Citation check.** Every answer must cite evidence ids, and every cited id must exist in the input.
4. **No invented facts.** Any CVE/GHSA id, version number or URL in the answer that does not appear in the input causes rejection.
5. **Bounded influence.** Priority may move at most one level from the computed score, and only as a visible suggestion with a stated reason.
6. **Safe fallback.** A rejected or failed answer is replaced by the deterministic explanation. The rejection reason is stored in the report and the audit log.
7. **Reproducibility.** Temperature 0. Prompts are versioned files (`prompts/*.md`) and their SHA-256 is recorded with every analysis. Answers are cached per (model, prompt hash, input).
8. **Labelled output.** In the report, inference is shown on a different background, next to (never instead of) the verified evidence.

These controls are unit-tested (`tests/test_day2.py::AIGuardrails`): invented CVE, invented version, unknown evidence id, and a two-level priority jump are all rejected.

## 3. Actions that need human approval

| Action | Who | Control |
|---|---|---|
| Any change to the code base (upgrade, override, pin, remove, replace, lockfile regeneration) | Named human | `guardian approve --by NAME --reason TEXT`; nothing is applied without it |
| Accepting a risk | Named human | Written reason + review date, shown as accepted residual risk in the report |
| Applying an approved option | Guardian | The option's SHA-256 is locked at approval time; if the plan changes, validation refuses to run |
| Merging, pushing, deploying, releasing | **Human only, outside the Guardian** | The Guardian creates a local branch in an isolated clone and stops. It has no push or merge code path. |
| Blocking a build | Policy file (reviewed like code) | `guardian gate --policy policies/default.json` exits 1; policies are versioned JSON |

Every step is written to `audit.jsonl`: an append-only, SHA-256 hash-chained log recording the actor (`guardian`, `ai:<model>`, `human:<name>`), the action and the input hashes. `guardian audit RUN` detects any edited, reordered or deleted entry (unit-tested).

## 4. How source code, credentials and secrets are protected

- **No source code goes to the model.** The import scan runs locally and only its *result* is shared ("imported by routes/order.ts"). File contents are never sent.
- **No secrets are read or sent.** The Guardian does not read `.env`, `.npmrc` tokens or credentials. Model API keys come from environment variables and are never written to disk, logs or reports.
- **Untrusted code is never run on the host checkout.**
  - Lockfiles are regenerated with `--ignore-scripts`, and installs during validation use `npm ci --ignore-scripts`.
  - Native modules are rebuilt explicitly (`npm rebuild sqlite3`), so install scripts from unreviewed packages do not execute.
  - Suspicious packages are only *read* (registry metadata, script text); they are never executed.
- **Isolation.** Validation works in fresh local clones (`work/before`, `work/after`). The user's checkout is never modified and nothing is pushed. For stronger isolation, run `guardian validate` inside a container or VM without credentials.
- **Read-only, public data sources.** OSV.dev, the npm registry and public git refs. No authentication is needed for public projects.
- **Out-of-scope activities are not implemented.** The Guardian does not scan production systems, publish packages, or touch other teams' infrastructure.

## 5. Known limitations

- **Reachability is package-level** (does production code import the package or its parent?), not function-level. Missing imports are treated as weak evidence because packages can be loaded dynamically (e.g. sequelize loading sqlite3).
- **Version matching depends on advisory-database coverage.** A brand-new malicious package is caught by the non-CVE detectors (typosquat, install script, registry take-down, tampering), not by CVE matching.
- **AI explanations are only as good as the evidence.** The guardrails stop invented facts, but cannot guarantee that the model's reasoning is correct. That is why scores are deterministic and approvals are human.
- **Container image contents** need syft (or an imported SBOM). In the hackathon sandbox, image pulls were blocked.
