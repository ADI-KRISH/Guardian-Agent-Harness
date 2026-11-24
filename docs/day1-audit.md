# Day 1 audit — 24 November 2026

The core Day 1 checkpoint is implemented and passes the current supported-repository check. This does not establish complete coverage for every ecosystem or verified upstream provenance.

## Checklist

| Requirement from Day 1 image | Evidence and assessment |
| --- | --- |
| Discover manifest and lockfile components, names and versions | `discovery.py`, `formats.py`; current demo checkout scan contains 1,274 package entries and reports complete inventory with no warnings |
| Identify direct and transitive dependencies | npm lockfile graph and nearest-installed dependency resolution are tested; unsupported or ambiguous ecosystem edges remain explicit coverage gaps |
| Generate or consume SBOM | CycloneDX JSON generation and import implemented; component links and transitive paths tested |
| Build dependency graph and identify origins | File/manifest origin and dependency paths are recorded; registry/publisher/source provenance is not comprehensively verified |
| Inspect a container or CI workflow | Static Dockerfile, Compose and workflow inspection implemented; current scan no longer has the prior YAML parser warning. Image-layer CVE scanning is separate and was not run here |
| Detect vulnerabilities, severity and available fixes | OSV exact-version matching, severity/aliases/raw CVSS, references and fixed boundaries are retained; cached coverage complete for all 1,274 current entries |
| Trace vulnerable transitives | Graph-backed dependency paths; unknown paths are not fabricated |
| Detect at least one suspicious change | Integrity changes, added dependencies, install scripts, execution signals, unpinned actions and images; baseline comparisons and representative rules have tests |
| Present evidence, affected component, path and initial risk | Finding drawer, graph, evidence, confidence, report/export and human review exist; facts and AI inference remain separate |

All 24 pre-existing automated tests passed. The expanded suite has 38 passing tests.

## Saved evaluation defect found during audit

The saved `verification/summary.json` claimed two false-negative candidates. Both exact advisory IDs were already in `guardian-7a261e9f6df6.json`:

- `netmask@1.0.6`: `GHSA-pch5-whg9-qr2r`
- `path-to-regexp@0.1.3`: `GHSA-9wv6-86v2-598j`

The comparison script selected an overlapping alias before an exact ID. Fixed `verify_guardian.py` to prefer exact identity, with a regression test. The historical report is preserved. `verification/day1-adjudication.json` records the offline adjudication. No fresh live precision/recall figure is asserted.

## Current repository check

A new scan of the existing `snyk-labs/nodejs-goof` checkout used offline mode and disabled dependency resolution. No install, build or fix was run.

- Scan: `4ea67ab9c938`
- Packages: 1,274
- Findings: 447
- Inventory: complete; no warnings
- Vulnerability coverage: complete using existing fresh cache, 1,274 / 1,274 entries
- Change comparison: available
- Machine-readable coverage: `verification/day1-current-check.json`

This checks the existing checkout, not the current remote repository or newly published advisories. The original saved scan had partial inventory because PyYAML was unavailable for Compose parsing; that warning is absent from the new scan.

## Day 2 review example

A pending plan was generated from the new scan:

- Plan: `R-c358eecf1dd9f78982408cae`
- Dependency: `mongoose`, `4.2.4` → candidate `5.13.15`
- Major compatibility change; advisory branch applicability, other advisories, lockfile regeneration and tests require validation.
- Status: pending human approval. No dependency change applied.

## Remaining boundaries

Comprehensive upstream provenance, runtime reachability and exploitability are not established. Some ecosystems provide inventory without complete transitive edges. Suspicious-source detection is heuristic, not proof of maliciousness. UI code was inspected and JavaScript syntax checked; this audit did not include a visual browser walkthrough. The remaining Day 2 execution and verification stages are outside the requested human-approval boundary.
