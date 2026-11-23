# Software Supply Chain Guardian

An agent harness that answers Bosch's Day 1 checkpoint for **any** repository:
**what is in the application, what changed, and what appears risky**, with evidence for every finding.

Design: see the team's design doc ("Guardian Agent Harness — Day 1 Design").

## Setup (Windows, no admin rights)

```powershell
cd supply-chain-guardian
powershell -ExecutionPolicy Bypass -File .\setup-tools.ps1   # syft, osv-scanner, actionlint, zizmor
uv sync                                                        # creates .venv with the guardian CLI
ollama pull llama3.2                                           # optional: local AI explanations (free, offline)
```

GuardDog 3.x does not build on Windows; when Docker Desktop is running the Guardian uses its official image instead.

## Use

```powershell
# Scan any public repo: compares the latest release tag (or --base) with the current default branch
.venv\Scripts\guardian scan https://github.com/juice-shop/juice-shop --base v20.0.0

# Human-in-the-loop
.venv\Scripts\guardian approve-baseline https://github.com/juice-shop/juice-shop v20.0.0 --by "Adithya" --reason "reviewed release"
.venv\Scripts\guardian label juice-shop SSCG-1A2B3C4D false_positive --by "Adithya" --reason "generated file"
.venv\Scripts\guardian add-lesson juice-shop --rule unpinned_image --scope "test/*" --by "Adithya" --reason "test images only"

# Tests (guardrails + detectors)
.venv\Scripts\python -m unittest discover -s tests -v
```

Reports go to `workspace\reports\<project>\<run-id>\`: `report.html`, `report.md`, `report.json` (machine-readable,
schema 1.0), `sbom.cdx.json` (CycloneDX), `inventory.json` (every package with origin, scope, hash, dependency graph)
and `decisions.json` (every decision with its reason).

## How a run works

1. **Plan**: the orchestrator picks the baseline (operator choice, else the latest human-approved baseline, else the latest tag) and logs why.
2. **Canary**: every detector must catch a planted sample first; a miss is reported as Critical.
3. **Discover**: Syft SBOM + lockfile parsing (npm, uv/poetry, requirements) -> packages, scope (runtime/dev), origin, integrity hash, install scripts, dependency graph, workflows, base images. Repos without a lockfile get one resolved with `npm install --package-lock-only --ignore-scripts` (no package code runs).
4. **Investigate in parallel**: Change agent (baseline diff, typosquats, hash changes, origin changes, new install scripts, downgrades), Vulnerability agent (OSV-Scanner + dependency paths), Container & CI agent (unpinned actions, zizmor, actionlint, base images), Backdoor agent (rules on added lines of the diff + GuardDog on new packages).
5. **Verify**: every cited file:line and package is re-checked against the checkout; duplicates merged; confidence set.
6. **Score**: severity x reach x new-since-baseline, explained in words; unverified findings can never be Critical.
7. **Explain**: the local LLM adds a short explanation, stored as *AI inference*, never as evidence.

## Guardrails (each has a test in `tests/`)

- Agents call named tools only, no free shell; child processes get an environment with secrets removed.
- Repository content is data: hooks are disabled on clone, package code is never run, AI-aimed text is flagged.
- Baselines, labels and lessons need a named human and a reason; the audit log is append-only.
- Lessons can never suppress backdoor, integrity, typosquat or canary findings.

## Open-source tools used

Syft (Apache-2.0), OSV-Scanner (Apache-2.0), zizmor (MIT), actionlint (MIT), GuardDog (Apache-2.0), Ollama (MIT),
Git, Python 3, SQLite. Design ideas (verifier gate, canaries, reachability verdicts) credited to 0security (MIT OR Apache-2.0).

## Known limitations

- Deep checks cover npm and PyPI; other ecosystems get SBOM + known-vulnerability checks only.
- When a repo commits no lockfile, versions are resolved at scan time, so "what changed" reflects manifest changes plus today's resolution.
- Backdoor rules are heuristics on the diff; they can miss well-hidden code and can flag benign code (that is what labels and lessons are for).
- Reachability (stretch goal 1) is not implemented yet: vulnerabilities are ranked by direct/transitive and runtime/dev scope.
