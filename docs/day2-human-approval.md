# Dynamic recommendation and sandbox validation

The workflow is now: scan → generate a repository-specific proposal → human approval → Docker copy/build/test → rescan → compare results. No package name, target upgrade version, repository URL or diff is hardcoded into the recommendation engine.

## How a fix is generated

1. Locate the affected dependency or configuration in the scanned source and verify its content hash. A finding's line number can refer to a lockfile, so the engine resolves the corresponding manifest declaration rather than blindly editing that line.
2. Obtain candidate versions from OSV advisory ranges and the registry’s current stable release; verify the release exists in npm/PyPI and query OSV for the candidate. Reject candidates still matched to known advisories. For pins, resolve the action's commit or image tag's digest using provider metadata.
3. Construct a before/after patch from those values and the repository's actual contents. Show the patch, compatibility concerns, checks to run, and missing prerequisites for human review.

OSV provides vulnerability information, not a certificate of safety. A version with no returned advisories can still be incompatible or have unknown vulnerabilities. Registry calls require connectivity unless advisory data remains in the 24-hour OSV cache; this is not an always-offline or instantaneous algorithm.

## Supported adapters

| Input | Generated proposal | Validation |
| --- | --- | --- |
| npm direct dependency | Exact manifest version, preserving unrelated JSON bytes | Regenerate npm lockfile, install without lifecycle scripts, run available build/test commands, rescan |
| npm transitive dependency | Explicit top-level override, with parent-compatibility warning | Same pipeline; reject unsupported nested overrides/workspaces |
| Exact Python requirements | Replace the matching pinned requirement, preserving markers/comments | Install wheels only, run configured commands; incomplete transitive inventory prevents a verified outcome |
| GitHub Action | Resolve release ref to commit SHA; preserve action subpath | Apply pin and run repository checks; rescan static workflow finding |
| Public Docker Hub FROM tag | Resolve immutable digest | Apply pin and run repository checks; rescan Dockerfile finding. Does not prove image contents are vulnerability-free |
| Suspected malicious behavior / other unsupported inputs | Evidence-backed investigation or escalation plan | No invented deletion or executable patch |

“Any repository” means recommendations are driven by that repository's findings, not demo identities. It does not mean universal automated repair. Maven, Go, Cargo, yarn/pnpm lockfile updates, monorepo workspace installation, private registries, arbitrary application bugs and complex migrations still need adapters or reviewed manual work. Stable three-component versions are currently supported for automatic candidate ordering; prerelease and other version schemes fall back to investigation.

## Approval and execution

Restart the Guardian server, open a finding, and select **Generate recommendation**. Review the candidate checks, diff and sandbox commands. **Approve & validate in sandbox** requires a reviewer name and reason and starts an asynchronous validation. Rejection never executes. Older proposals generated before sandbox support need regeneration.

The stored immutable proposal content includes exact edited contents, original hashes and the command profile. The worker rechecks the complete source snapshot, including changes outside the target file. It runs only approved proposals and never modifies the original checkout. A failed/blocked approved proposal can be retried; changed source requires a new scan and approval.

The validator copies inventoried files into `.guardian/repositories/sandbox-<validation-id>`, omits common credential/config files, and restores hash-verified generated lockfile artifacts when present. It scans the unchanged copy, applies the approved edit, then runs container commands. Containers receive only the disposable copy: no original checkout, host home or Docker socket. They run as a non-root user with dropped capabilities, a read-only root filesystem, process/CPU/memory/time/log limits and no host environment credentials. Registry installation uses network access with lifecycle scripts disabled; build/test commands have networking disabled. Containers are removed after each command; the workspace and report remain for review.

Docker is an isolation boundary, not a claim of perfect protection. Keep Docker Desktop updated. Dependency installation currently permits public npm registry artifacts and exact wheel-installable Python requirements; private/local/git dependency forms fail explicitly.

## Docker setup

Install and start Docker Desktop, then pull the runtime needed for your repository:

```sh
docker pull node:22-bookworm-slim
# For Python validation:
docker pull python:3.12-slim
```

Images must already exist locally. The worker resolves the selected image to an immutable local image ID for the entire validation; it does not silently pull or run repository-provided Dockerfiles. Administrator environment variables `GUARDIAN_SANDBOX_NODE_IMAGE` and `GUARDIAN_SANDBOX_PYTHON_IMAGE` can select preinstalled images.

## Repository test configuration

For npm, existing `build` and `test` scripts are detected. For another supported runtime or explicit command selection, include `.guardian-validation.json` in the scanned repository:

```json
{
  "runtime": "python",
  "test": ["python", "-m", "unittest", "discover", "-s", "tests"]
}
```

Commands are argument arrays, shown before approval, and run inside the container without networking. The configuration must exist before scanning. Python test dependencies must be present in the chosen requirements/image; no test framework is silently installed.

## Report meanings

- **Verified:** target reproduced before and absent after; configured commands passed; a test command ran successfully; both scans have complete supported coverage; no new high/critical/unknown findings were introduced.
- **Failed:** command failed, target persists, new high/critical/unknown risks appeared, or build/test altered dependency evidence.
- **Inconclusive:** target disappeared but tests or coverage are insufficient.
- **Blocked:** missing runtime/image, stale source, unreproducible target or unsupported prerequisites.

A successful test process is evidence about that configured command, not proof of complete behavioral coverage. New lower-severity and remaining findings are included in the report and must still be reviewed. No automatic commit, PR, merge or production deployment occurs.

Reports include baseline/rescan IDs, container image ID, commands and logs, SBOM added/removed versions, target outcome, new findings and remaining risk. The UI opens the rescanned sandbox and exports the full JSON report. Missing Docker never falls back to running repository code on the host.

## API

All POST endpoints use the existing same-origin session token.

- `POST /api/remediation/recommend`: `scan_id`, `finding_id`.
- `POST /api/remediation/decision`: `plan_id`, `status`, `actor`, `reason`; `validate: true` starts an approved executable plan.
- `POST /api/remediation/validate`: retry/start an already approved `plan_id`.
- `GET /api/validations/{id}`: persisted progress/result.
- `GET /api/scans/{id}/remediations`: plans, decisions and latest validation.

Reviewer names are self-asserted local identities. Audit is append-only via SQLite triggers, not cryptographically signed enterprise authorization. Approval does not relabel the original scan as resolved; validation produces its own evidence.

## Role of an LLM

An LLM is unnecessary for registry-backed version changes and immutable pins. Deterministic adapters produce the patches and enforce their preconditions. The existing optional local Ollama investigator explains findings; its prose remains unverified inference. A future LLM migration suggestion must cite release documentation, become an explicit reviewable patch, and pass the same approval/sandbox/rescan pipeline. It cannot invent trusted versions, approve changes or declare a fix verified.

## Tests

Run `.venv/bin/python -m unittest discover -s tests -v` for unit/API and controlled pipeline tests. The opt-in live Docker test is `.venv/bin/python tests/smoke_docker.py`. It creates a disposable intentionally vulnerable fixture, selects an upgrade from live registry/OSV data, records a clearly labelled fixture-only approval, runs Docker tests and rescans. It does not approve any user-repository change.


## Verified integration run (24 November 2026)

The real Docker integration test completed successfully with live registry and OSV queries. The engine selected `lodash 4.18.1` for an intentionally vulnerable `4.17.20` fixture after older candidates still matched advisories. It regenerated the lockfile, installed dependencies with lifecycle scripts disabled, passed a functional test without network access, and rescanned. The target was reproduced before and absent afterward; both scans had complete supported coverage and no new high/critical/unknown findings. A lower-severity dependency-added observation remains reported. The original fixture was unchanged.

Evidence: `verification/day2-docker-smoke.json`. The earlier 52 automated tests use controlled provider/container fixtures where indicated; the integration report records actual Docker execution. This demonstrates the supported pipeline, not universal compatibility across repositories.
