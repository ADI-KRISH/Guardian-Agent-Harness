# Design-to-implementation scope

| Design capability | Current state |
|---|---|
| Manifest/lockfile inventory | Implemented native readers with explicit coverage gaps |
| CycloneDX generation/consumption | Implemented JSON |
| Direct/transitive dependency graph | Implemented where input provides resolvable relationships |
| Knowledge graph visualization | Implemented interactive SVG with package, finding and evidence nodes |
| Known vulnerability matching | Implemented live OSV exact-version queries and cache |
| CI or container inspection | Implemented workflow and Dockerfile static analysis |
| Dependency/hash changes | Implemented snapshot comparisons |
| Backdoor signals | Implemented deterministic heuristics; not proof of malware |
| Orchestration and five memories | Implemented deterministic stages, SQLite and JSON snapshots |
| Human reviews and baseline gates | Implemented UI and CLI |
| Learning loop | Implemented exact scoped expiring suppressions with fixture gate and approval |
| Evidence and audit | Implemented reports, scores, paths, status, audit trail |
| Evaluation | 11 planted/clean cases plus 24 automated tests |
| Syft/GuardDog/Semgrep/Grype/Trivy adapters | Not implemented; no tool output is simulated |
| Package/source release comparison | Not implemented |
| Source Git hunks, image digest history, nested action chains | Not implemented |
| Independent second-signal verification | Not implemented; confidence stays Medium |
| AI investigator, model/token budgets | Not configured; no model calls |
| Native network/container enforcement | Offline container recipe provided; local process is not sandboxed |
| Reachability/provenance/maintainer analysis | Stretch capabilities not implemented |
| Remediation recommendations and human approval | Implemented; see day2-human-approval.md |
| Sandbox build/test/rescan | Docker-only pipeline with strict snapshot, build+test gating, rescan-only opt-in mode; unit-tested with mocked containers, live Docker run recorded in verification/ |
| Commit approved fix to a review branch | Implemented behind a second human approval; local branch only |
| Automatic push / PR / merge / production deployment | Not implemented by design |

The runnable product closes the central Day 1 loop. The remaining design capabilities above are explicit boundaries, not hidden successful checks.
