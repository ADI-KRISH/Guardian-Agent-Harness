# Remediation plan: shop-api@1.4.0

No change is applied without an explicit human approval recorded in this plan. The Guardian never pushes, merges, deploys or releases.

## R1 · P1-urgent · score 100 · lodash@4.17.15: integrity, vulnerability
Status: **pending-approval**

Path: shop-api@1.4.0 > lodash@4.17.15
Reachability: unknown · Exposure: server

- **R1.a upgrade** ⭐ recommended: Upgrade lodash 4.17.15 -> 4.18.0 (minor)
  - risk reduction: 6 finding(s), score -497 (expected; confirmed by rescan during validation)
  - compatibility: low (semver minor change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R1.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R1.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R1 --option <id> --by "Name" --reason "..."`

## R2 · P1-urgent · score 100 · flatmap-stream@0.1.1: malicious-package, vulnerability
Status: **pending-approval**

Path: shop-api@1.4.0 > event-stream@3.3.6 > flatmap-stream@0.1.1
Reachability: unknown · Exposure: server

- **R2.a remove** ⭐ recommended: Remove 'flatmap-stream' and regenerate the lockfile; block it in policy
  - risk reduction: 3 finding(s), score -300 (expected; confirmed by rescan during validation)
  - compatibility: low (no source file imports it)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R2.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R2 --option <id> --by "Name" --reason "..."`

## R3 · P1-urgent · score 100 · ua-parser-js@0.7.29: integrity, malicious-package
Status: **pending-approval**

Path: —
Reachability: orphan · Exposure: server

- **R3.a remove** ⭐ recommended: Remove 'ua-parser-js' and regenerate the lockfile; block it in policy
  - risk reduction: 2 finding(s), score -175 (expected; confirmed by rescan during validation)
  - compatibility: low (no source file imports it)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R3.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R3 --option <id> --by "Name" --reason "..."`

## R4 · P1-urgent · score 100 · event-stream@3.3.6: integrity, vulnerability
Status: **pending-approval**

Path: shop-api@1.4.0 > event-stream@3.3.6
Reachability: unknown · Exposure: server

- **R4.a upgrade** ⭐ recommended: Upgrade event-stream 3.3.6 -> 4.0.0 (major)
  - risk reduction: 2 finding(s), score -175 (expected; confirmed by rescan during validation)
  - compatibility: high (semver major change; breaking API changes possible; build + tests must pass before approval is final)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R4.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R4.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R4 --option <id> --by "Name" --reason "..."`

## R5 · P1-urgent · score 100 · minimist@1.2.5: integrity, vulnerability
Status: **pending-approval**

Path: shop-api@1.4.0 > minimist@1.2.5
Reachability: unknown · Exposure: server

- **R5.a upgrade** ⭐ recommended: Upgrade minimist 1.2.5 -> 1.2.6 (patch)
  - risk reduction: 3 finding(s), score -250 (expected; confirmed by rescan during validation)
  - compatibility: low (semver patch change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R5.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R5.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R5 --option <id> --by "Name" --reason "..."`

## R6 · P1-urgent · score 100 · crossenv@6.1.1: install-script, malicious-package, typosquat
Status: **pending-approval**

Path: shop-api@1.4.0 > crossenv@6.1.1
Reachability: unknown · Exposure: dev-tooling

- **R6.a remove** ⭐ recommended: Remove 'crossenv' and regenerate the lockfile; block it in policy
  - risk reduction: 3 finding(s), score -270 (expected; confirmed by rescan during validation)
  - compatibility: low (no source file imports it)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R6.b replace**: Replace 'crossenv' with the intended package 'cross-env'
  - risk reduction: 3 finding(s), score -270 (expected; confirmed by rescan during validation)
  - compatibility: low (same intended functionality)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R6.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R6 --option <id> --by "Name" --reason "..."`

## R7 · P1-urgent · score 95 · body-parser@1.19.0: 2 known vulnerabilities
Status: **pending-approval**

Path: shop-api@1.4.0 > express@4.17.1 > body-parser@1.19.0
Reachability: parent-imported · Exposure: server

- **R7.a upgrade-parent** ⭐ recommended: Upgrade direct dependency express 4.17.1 -> 4.22.0 (minor); express@4.22.0 requires body-parser ~1.20.3, which admits a fixed version
  - risk reduction: 2 finding(s), score -190 (expected; the parent upgrade may also change other transitive packages)
  - compatibility: low (semver minor change; 1 source file(s) import express: server.js)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R7.b override**: Force body-parser@1.20.9 with npm overrides
  - risk reduction: 2 finding(s), score -190 (expected; confirmed by rescan during validation)
  - compatibility: high (outside the declared range (express declares 1.19.0): parent may break)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R7.c accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R7.d escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R7 --option <id> --by "Name" --reason "..."`

## R8 · P1-urgent · score 95 · path-to-regexp@0.1.7: 3 known vulnerabilities
Status: **pending-approval**

Path: shop-api@1.4.0 > express@4.17.1 > path-to-regexp@0.1.7
Reachability: parent-imported · Exposure: server

- **R8.a upgrade-parent** ⭐ recommended: Upgrade direct dependency express 4.17.1 -> 4.22.0 (minor); express@4.22.0 requires path-to-regexp ~0.1.12, which admits a fixed version
  - risk reduction: 3 finding(s), score -285 (expected; the parent upgrade may also change other transitive packages)
  - compatibility: low (semver minor change; 1 source file(s) import express: server.js)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R8.b override**: Force path-to-regexp@0.1.13 with npm overrides
  - risk reduction: 3 finding(s), score -285 (expected; confirmed by rescan during validation)
  - compatibility: high (outside the declared range (express declares 0.1.7): parent may break)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R8.c accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R8.d escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R8 --option <id> --by "Name" --reason "..."`

## R9 · P1-urgent · score 95 · qs@6.7.0: 3 known vulnerabilities
Status: **pending-approval**

Path: shop-api@1.4.0 > express@4.17.1 > qs@6.7.0
Reachability: parent-imported · Exposure: server

- **R9.a upgrade-parent** ⭐ recommended: Upgrade direct dependency express 4.17.1 -> 4.22.3 (minor); express@4.22.3 requires qs ~6.16.0, which admits a fixed version
  - risk reduction: 3 finding(s), score -241 (expected; the parent upgrade may also change other transitive packages)
  - compatibility: low (semver minor change; 1 source file(s) import express: server.js)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R9.b override**: Force qs@6.16.1 with npm overrides
  - risk reduction: 3 finding(s), score -241 (expected; confirmed by rescan during validation)
  - compatibility: high (outside the declared range (body-parser declares 6.7.0; express declares 6.7.0): parent may break)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R9.c accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R9.d escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R9 --option <id> --by "Name" --reason "..."`

## R10 · P1-urgent · score 88 · node-fetch@2.6.0: 1 known vulnerability
Status: **pending-approval**

Path: shop-api@1.4.0 > node-fetch@2.6.0
Reachability: unknown · Exposure: server

- **R10.a upgrade** ⭐ recommended: Upgrade node-fetch 2.6.0 -> 2.6.7 (patch)
  - risk reduction: 1 finding(s), score -88 (expected; confirmed by rescan during validation)
  - compatibility: low (semver patch change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R10.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R10.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R10 --option <id> --by "Name" --reason "..."`

## R11 · P2-high · score 76 · express@4.17.1: 2 known vulnerabilities
Status: **pending-approval**

Path: shop-api@1.4.0 > express@4.17.1
Reachability: imported · Exposure: server

- **R11.a upgrade** ⭐ recommended: Upgrade express 4.17.1 -> 4.20.0 (minor)
  - risk reduction: 2 finding(s), score -141 (expected; confirmed by rescan during validation)
  - compatibility: low (semver minor change; 1 source file(s) import express: server.js)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R11.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R11.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R11 --option <id> --by "Name" --reason "..."`

## R12 · P2-high · score 75 · Dockerfile: RUN pipes a downloaded script into a shell
Status: **pending-approval**

Path: —
Reachability: n/a · Exposure: runtime-image

- **R12.a escalate** ⭐ recommended: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R12.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R12 --option <id> --by "Name" --reason "..."`

## R13 · P2-high · score 75 · quick-actions/npm-cache@main: cicd
Status: **pending-approval**

Path: —
Reachability: n/a · Exposure: ci-pipeline

- **R13.a escalate** ⭐ recommended: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R13 --option <id> --by "Name" --reason "..."`

## R14 · P2-high · score 75 · fastbuilds/node-runtime@18: untrusted-image
Status: **pending-approval**

Path: —
Reachability: n/a · Exposure: runtime-image

- **R14.a pin** ⭐ recommended: Pin 'fastbuilds/node-runtime' to an explicit version tag + sha256 digest from a trusted registry (digest lookup needs registry access; filled in by the reviewer)
  - risk reduction: 1 finding(s), score -75 (expected; confirmed by rescan during validation)
  - compatibility: low (same image if pinned to the current digest)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R14.b escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R14 --option <id> --by "Name" --reason "..."`

## R15 · P2-high · score 75 · debug-helper-utils@1.0.2: unexpected-dependency
Status: **pending-approval**

Path: shop-api@1.4.0 > debug-helper-utils@1.0.2
Reachability: unknown · Exposure: server

- **R15.a lock-regenerate** ⭐ recommended: Regenerate the lockfile from package.json using the public registry (drops injected entries and re-fetches trusted hashes)
  - risk reduction: 1 finding(s), score -75 (expected; confirmed by rescan during validation)
  - compatibility: medium (other transitive versions may move within their ranges)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R15.b escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R15 --option <id> --by "Name" --reason "..."`

## R16 · P2-high · score 75 · Untrusted event data interpolated into a workflow step
Status: **pending-approval**

Path: —
Reachability: n/a · Exposure: ci-pipeline

- **R16.a escalate** ⭐ recommended: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R16.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R16 --option <id> --by "Name" --reason "..."`

## R17 · P2-high · score 60 · send@0.17.1: 1 known vulnerability
Status: **pending-approval**

Path: shop-api@1.4.0 > express@4.17.1 > send@0.17.1
Reachability: parent-imported · Exposure: server

- **R17.a upgrade-parent** ⭐ recommended: Upgrade direct dependency express 4.17.1 -> 4.20.0 (minor); express@4.20.0 requires send 0.19.0, which admits a fixed version
  - risk reduction: 1 finding(s), score -60 (expected; the parent upgrade may also change other transitive packages)
  - compatibility: low (semver minor change; 1 source file(s) import express: server.js)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R17.b override**: Force send@0.19.0 with npm overrides
  - risk reduction: 1 finding(s), score -60 (expected; confirmed by rescan during validation)
  - compatibility: high (outside the declared range (express declares 0.17.1; serve-static declares 0.17.1): parent may break)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R17.c accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R17.d escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R17 --option <id> --by "Name" --reason "..."`

## R18 · P2-high · score 60 · serve-static@1.14.1: 1 known vulnerability
Status: **pending-approval**

Path: shop-api@1.4.0 > express@4.17.1 > serve-static@1.14.1
Reachability: parent-imported · Exposure: server

- **R18.a upgrade-parent** ⭐ recommended: Upgrade direct dependency express 4.17.1 -> 4.20.0 (minor); express@4.20.0 requires serve-static 1.16.0, which admits a fixed version
  - risk reduction: 1 finding(s), score -60 (expected; the parent upgrade may also change other transitive packages)
  - compatibility: low (semver minor change; 1 source file(s) import express: server.js)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R18.b override**: Force serve-static@1.16.0 with npm overrides
  - risk reduction: 1 finding(s), score -60 (expected; confirmed by rescan during validation)
  - compatibility: high (outside the declared range (express declares 1.14.1): parent may break)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R18.c accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R18.d escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R18 --option <id> --by "Name" --reason "..."`
