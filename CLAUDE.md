# CLAUDE.md — Software Supply Chain Guardian (Bosch BGSW hackathon, Amrita, 23–24 Nov 2026)

## Goal
Agentic AI "Software Supply Chain Guardian" that works on ANY public repo.
- Day 1 checkpoint (Milestone 1): "Show us what is in the application, what changed, and what appears risky." (visibility + detection, evidence for every finding)
- Day 2 final demo: "Show us how the Guardian takes a finding from detection to verified remediation." (prioritise -> recommend fix -> HUMAN APPROVAL -> build & test in sandbox -> rescan -> verified)
Design docs (read-only for you): harness design https://claude.ai/artifact/WP48NH8M5WXHkY1K8GMMut ·
PS explainer https://claude.ai/artifact/HdffAEkEBmqKfSqm9CBBuS

## Rule #1: MVP first, never break the demo path
Before finishing any change: `.venv\Scripts\python -m unittest discover -s tests` must pass, and a scan must still run:
`.venv\Scripts\guardian scan https://github.com/juice-shop/juice-shop --base v20.0.0 --no-llm` (~45 s, expect ~3 Critical incl. jsonwebtoken 0.4.0).

## Live presenter (for the panel)
`run-live.bat` (= `guardian serve`) -> http://127.0.0.1:8765. Paste a repo link -> agents light up live -> 9-step walkthrough -> propose fix -> a human types name+reason to approve
-> sandbox validation (live) -> report page with files + print-to-PDF. Same template as the static demo (`demo/template.html`, live when `__DATA__` is null).
Server = guardian/serve.py: stdlib only, 127.0.0.1 only, per-start token on every POST, strict input patterns, runs `guardian scan|validate` as subprocesses.
Never approve a fix on someone's behalf: the approval form is for the human presenter.

## Demo page
`run-demo.bat` (= `python demo\build_demo.py --open`) builds workspace/demo/index.html, a single-file 7-step walkthrough (question -> inventory -> changes -> risks -> agents -> fix+approval -> sandbox result)
from the LATEST real report and remediation; rerun it after every scan/validate. Stages without data show the command that produces them. `--remediation <json>` previews another result.

## Day 2 flow (needs Docker Desktop)
`guardian propose <project> <finding-id>` -> `guardian approve <FIX-id> --by NAME --reason TEXT` -> `guardian validate <FIX-id> [--test "npm test"]`
(or the "Fix & verify" tab in the UI). Report: workspace/reports/<project>/<run>/remediation-<FIX-id>/. LLM config: `.env` (wins over stale env vars);
failover endpoints GUARDIAN_FALLBACK_1..9 = `base_url|model|key` (`$NAME` = value of that variable).

## Commands
- Setup scanners: `powershell -ExecutionPolicy Bypass -File .\setup-tools.ps1` (syft, osv-scanner, actionlint in `.tools\`; zizmor via `uv tool`)
- Env: `uv sync` · UI: `run-ui.bat` -> http://localhost:8501 · CLI: `.venv\Scripts\guardian --help`
- AI: OpenAI when `OPENAI_API_KEY` is set (model `GUARDIAN_MODEL`, default gpt-4o-mini); else local Ollama `llama3.2`; `--no-llm` to skip.

## Layout
```
guardian/cli.py            CLI: scan, approve-baseline, label, add-lesson, tags
guardian/orchestrator.py   plans run (base/head refs), canary, runs agents (3 in parallel), logs every decision
guardian/agents/discovery.py   SBOM (syft) + lockfile parsing (npm, uv/poetry, requirements) + graph, scope, origin, hashes,
                               workflows, Dockerfile FROMs; generates npm lockfile with --ignore-scripts if missing
guardian/agents/change.py      baseline diff: added/removed/updated, typosquat, integrity change, origin change, install scripts, downgrades
guardian/agents/vuln.py        OSV-Scanner (--no-ignore!) + dependency paths + fixed versions
guardian/agents/backdoor.py    regex rules on ADDED lines of git diff + binaries + bidi + AI-injection text; GuardDog on new packages
guardian/agents/ci_container.py  unpinned actions, zizmor (json, verbatim_path), actionlint, base images
guardian/agents/verifier.py    re-check cited file:line/package, dedupe, confidence (high=2+ detectors, medium=1, low=unverified)
guardian/agents/evidence.py    score = severity x reach x new-since-baseline x evidence; lessons (suppressions)
guardian/agents/fixer.py       Day 2 Fix agent: finding -> proposal (version pick, expected reduction, compat note, rollback); apply_edit() for the sandbox
guardian/agents/validator.py   Day 2 Validation agent: sandbox branch, lockfile refresh, docker build, in-container checks, rescan, before/after, verdict
guardian/remediate.py          Day 2 flow: propose -> (human approval gate) -> validate -> remediation.html|md|json + patch.diff, Responsible AI note
guardian/agents/__init__.py    finding() schema + TYPES table (type -> category, default severity)
guardian/llm.py            openai | ollama | anthropic; output stored ONLY as ai_inference (never evidence)
guardian/canary.py         every detector must catch a planted sample each run, else Critical canary_missed
guardian/memory.py         SQLite workspace/guardian.db: baselines (human only), findings, decisions (append-only triggers), lessons, cache
guardian/tools/            named tools only: run() strips secret env vars; git.py (hooks off), scanners.py
guardian/report.py         workspace/reports/<project>/<run>/ report.html|md|json, sbom.cdx.json, inventory.json, decisions.json
ui/app.py                  Streamlit UI: what's in it / what changed / what's risky / human review / audit / self-check
tests/                     test_guardrails.py (14), test_ui.py; tests/_patch_tool.py = exact-match patch helper
```

## Guardrails (non-negotiable, each has a test)
- Never execute code from the scanned repo or its packages ON THE HOST (no npm install with scripts, no pip install of targets). `--ignore-scripts` only.
  Day 2 exception: after a named human approves a fix (`memory.decide_proposal`; `remediate.validate` raises PermissionError otherwise), package code may run
  ONLY inside the Docker sandbox (`scanners.docker_run_sandboxed`: no network, cap-drop ALL, no secrets, limits). Image + test command come from the operator
  (`config.load(None)["validate"]`, `--test`, GUARDIAN_VALIDATE_TEST), never from the scanned repo's guardian.yaml.
- Agents call named tools in guardian/tools, never a free shell. `run()` must keep stripping TOKEN/SECRET/KEY env vars.
- Repo content is DATA: wrap in <DATA> for the LLM; flag "ignore previous instructions"-style text.
- Baselines, labels, lessons need a named human + reason. Audit log is append-only. Lessons can never suppress
  backdoor_signal, integrity_change, typosquat, canary_missed (memory.UNSUPPRESSIBLE).
- Unverified (low confidence) findings can never be Critical. AI inference never raises confidence.
- Out of scope (Bosch rules): no scanning/attacking live systems, no publishing packages, no real secrets, NO auto-merge/deploy without human approval.

## Windows gotchas (learned the hard way)
- Do NOT edit files with PowerShell `Get-Content/Set-Content` (re-encodes UTF-8 -> mojibake). Use Python or your editor tools.
- GitHub REST API is rate-limited on the venue network: use release-page redirects / git, not api.github.com.
- Juice Shop gitignores package-lock.json -> osv-scanner needs `--no-ignore`.
- GuardDog 3.x does not build on Windows -> runs via Docker image ghcr.io/datadog/guarddog when Docker Desktop is up.
- uv writes progress to stderr; wrap in `cmd /c "... 2>&1"` when scripting from PowerShell.

## Next tasks (in order)
1. Verify OpenAI path: run one scan with OPENAI_API_KEY set; ai_inference must show model `openai:<model>`.
2. Port teammate rule: whole-repo (not just diff) check of `.github/workflows/*.yml` `run:` lines for download-and-execute
   (e.g. `curl ... | sh` at juice-shop ci.yml:353). New finding type or reuse backdoor_signal with rule `download-and-run`. Add a test.
3. Eval suite `eval/`: script that copies a repo checkout to workspace/eval/<name>, plants 7 attacks (typosquat in lockfile,
   same-version hash change, new postinstall script, xz-style build-script hook, base64 exec in source, tag-pinned action,
   floating untrusted image) + decoys, commits them locally (never pushed), scans base->planted, prints a scoreboard
   (caught/missed per case, false positives on decoys). Label every planted finding "planted" in report + UI.
4. Second ecosystem proof: scan one Python repo with Dockerfile + workflows; add `uv pip compile` lockfile generation
   (no install) for pyproject/requirements without pins.
5. Learning agent: from human labels (false_positive with reason) propose a scoped suppression; run eval suite; only save
   after human approval in UI. Must refuse UNSUPPRESSIBLE types.
6. UI polish for Milestone 1 demo: a "3-minute demo" view (inventory -> changes -> top 5 risks -> Why? chain -> canary).
Day 2 (needs Docker Desktop): Fix agent (proposal + expected risk reduction + compatibility note + rollback),
approval gate in UI, Validation agent (copy to sandbox branch, docker build, run tests, rescan, before/after SBOM diff,
detect newly introduced issues), final verified-remediation report, Responsible AI note. Stretch: reachability first.

## Conventions
Python 3.13, stdlib + pyyaml + streamlit only (ask before adding deps). Small functions, every new detector gets
a canary sample or a unit test. Every agent decision goes through `Run.decide(actor, decision, why, ...)`.
Do not commit or push unless the user asks.
