# Remediation plan: juice-shop@20.4.0-SNAPSHOT

No change is applied without an explicit human approval recorded in this plan. The Guardian never pushes, merges, deploys or releases.

## R1 · P1-urgent · score 100 · crypto-js@3.3.0: 2 known vulnerabilities
Status: **approved** (by TEST-RUN by Claude (not a real human approval): critical crypto-js weakness reachable via pdfkit (routes/order.ts); upgrade parent pdfkit 0.11 -> 0.12)

Path: juice-shop@20.4.0-SNAPSHOT > pdfkit@0.11.0 > crypto-js@3.3.0
Reachability: parent-imported · Exposure: server

- **R1.a upgrade-parent** ⭐ recommended: Upgrade direct dependency pdfkit 0.11.0 -> 0.12.2 (major); pdfkit@0.12.2 requires crypto-js ^4.0.0, which admits a fixed version
  - risk reduction: 2 finding(s), score -200 (expected; the parent upgrade may also change other transitive packages)
  - compatibility: high (semver major change; 1 source file(s) import pdfkit: routes/order.ts; breaking API changes possible; build + tests must pass before approval is final)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R1.b override**: Force crypto-js@4.2.0 with npm overrides
  - risk reduction: 2 finding(s), score -200 (expected; confirmed by rescan during validation)
  - compatibility: high (outside the declared range (pdfkit declares ^3.1.9-1): parent may break)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R1.c accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R1.d escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R1 --option <id> --by "Name" --reason "..."`

## R2 · P1-urgent · score 100 · jsonwebtoken@0.1.0: 4 known vulnerabilities
Status: **risk-accepted** (by TEST-RUN by Claude (not a real human approval): Juice Shop is intentionally vulnerable; JWT challenges rely on jsonwebtoken 0.1.0)

Path: juice-shop@20.4.0-SNAPSHOT > express-jwt@0.1.3 > jsonwebtoken@0.1.0
Reachability: imported · Exposure: server

- **R2.a upgrade-parent** ⭐ recommended: Upgrade direct dependency express-jwt 0.1.3 -> 7.7.8 (major); express-jwt@7.7.8 requires jsonwebtoken ^9.0.2, which admits a fixed version
  - risk reduction: 4 finding(s), score -354 (expected; the parent upgrade may also change other transitive packages)
  - compatibility: high (semver major change; 1 source file(s) import express-jwt: lib/insecurity.ts; breaking API changes possible; build + tests must pass before approval is final)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R2.b override**: Force jsonwebtoken@9.0.0 with npm overrides
  - risk reduction: 4 finding(s), score -354 (expected; confirmed by rescan during validation)
  - compatibility: high (outside the declared range (express-jwt declares ~0.1.0): parent may break)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R2.c accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R2.d escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R2 --option <id> --by "Name" --reason "..."`

## R3 · P1-urgent · score 100 · jsonwebtoken@0.4.0: 4 known vulnerabilities
Status: **risk-accepted** (by TEST-RUN by Claude (not a real human approval): intentionally vulnerable training dependency (JWT challenges))

Path: juice-shop@20.4.0-SNAPSHOT > jsonwebtoken@0.4.0
Reachability: imported · Exposure: server

- **R3.a upgrade** ⭐ recommended: Upgrade jsonwebtoken 0.4.0 -> 9.0.0 (major)
  - risk reduction: 4 finding(s), score -354 (expected; confirmed by rescan during validation)
  - compatibility: high (semver major change; 4 source file(s) import jsonwebtoken: lib/insecurity.ts, routes/authenticatedUsers.ts, routes/verify.ts; breaking API changes possible; build + tests must pass before approval is final)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R3.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R3.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R3 --option <id> --by "Name" --reason "..."`

## R4 · P1-urgent · score 100 · jws@0.2.6: 2 known vulnerabilities
Status: **pending-approval**

Path: juice-shop@20.4.0-SNAPSHOT > jsonwebtoken@0.4.0 > jws@0.2.6
Reachability: imported · Exposure: server

- **R4.a upgrade-parent** ⭐ recommended: Upgrade direct dependency jsonwebtoken 0.4.0 -> 5.0.0 (major); jsonwebtoken@5.0.0 requires jws ^3.0.0, which admits a fixed version
  - risk reduction: 2 finding(s), score -200 (expected; the parent upgrade may also change other transitive packages)
  - compatibility: high (semver major change; 4 source file(s) import jsonwebtoken: lib/insecurity.ts, routes/authenticatedUsers.ts, routes/verify.ts; breaking API changes possible; build + tests must pass before approval is final)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R4.b override**: Force jws@3.2.3 with npm overrides
  - risk reduction: 2 finding(s), score -200 (expected; confirmed by rescan during validation)
  - compatibility: high (outside the declared range (jsonwebtoken declares ~0.2.2): parent may break)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R4.c accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R4.d escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R4 --option <id> --by "Name" --reason "..."`

## R5 · P1-urgent · score 100 · lodash@2.4.2: 4 known vulnerabilities
Status: **pending-approval**

Path: juice-shop@20.4.0-SNAPSHOT > sanitize-html@1.4.2 > lodash@2.4.2
Reachability: parent-imported · Exposure: server

- **R5.a upgrade-parent** ⭐ recommended: Upgrade direct dependency sanitize-html 1.4.2 -> 1.7.1 (minor); sanitize-html@1.7.1 no longer depends on lodash
  - risk reduction: 4 finding(s), score -342 (expected; the parent upgrade may also change other transitive packages)
  - compatibility: low (semver minor change; 2 source file(s) import sanitize-html: lib/insecurity.ts, lib/challengeUtils.ts)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R5.b override**: Force lodash@4.17.21 with npm overrides
  - risk reduction: 4 finding(s), score -342 (expected; confirmed by rescan during validation)
  - compatibility: high (outside the declared range (sanitize-html declares 2.4.x): parent may break)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R5.c accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R5.d escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R5 --option <id> --by "Name" --reason "..."`

## R6 · P1-urgent · score 100 · marsdb@0.6.11: 1 known vulnerability
Status: **pending-approval**

Path: juice-shop@20.4.0-SNAPSHOT > marsdb@0.6.11
Reachability: imported · Exposure: server

- **R6.a mitigate** ⭐ recommended: No fixed version available: restrict use of the affected function / input, or replace the package
  - risk reduction: 0 finding(s), score -0 (manual mitigation; risk remains until replaced)
  - compatibility: unknown (manual change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R6.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R6.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R6 --option <id> --by "Name" --reason "..."`

## R7 · P1-urgent · score 100 · sanitize-html@1.4.2: 10 known vulnerabilities
Status: **pending-approval**

Path: juice-shop@20.4.0-SNAPSHOT > sanitize-html@1.4.2
Reachability: imported · Exposure: server

- **R7.a upgrade** ⭐ recommended: Upgrade sanitize-html 1.4.2 -> 2.18.0 (major)
  - risk reduction: 10 finding(s), score -761 (expected; confirmed by rescan during validation)
  - compatibility: high (semver major change; 2 source file(s) import sanitize-html: lib/insecurity.ts, lib/challengeUtils.ts; breaking API changes possible; build + tests must pass before approval is final)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R7.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R7.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R7 --option <id> --by "Name" --reason "..."`

## R8 · P1-urgent · score 95 · moment@2.0.0: 3 known vulnerabilities
Status: **pending-approval**

Path: juice-shop@20.4.0-SNAPSHOT > express-jwt@0.1.3 > jsonwebtoken@0.1.0 > moment@2.0.0
Reachability: parent-imported · Exposure: server

- **R8.a override** ⭐ recommended: Force moment@2.29.2 with npm overrides
  - risk reduction: 3 finding(s), score -270 (expected; confirmed by rescan during validation)
  - compatibility: high (outside the declared range (jsonwebtoken declares ~2.0.0): parent may break)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R8.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R8.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R8 --option <id> --by "Name" --reason "..."`

## R9 · P1-urgent · score 95 · uuid@8.3.2: 1 known vulnerability
Status: **pending-approval**

Path: juice-shop@20.4.0-SNAPSHOT > sequelize@6.37.8 > uuid@8.3.2
Reachability: parent-imported · Exposure: server

- **R9.a override** ⭐ recommended: Force uuid@11.1.1 with npm overrides
  - risk reduction: 1 finding(s), score -95 (expected; confirmed by rescan during validation)
  - compatibility: high (outside the declared range (istanbul-lib-processinfo declares ^8.3.2; sequelize declares ^8.3.2): parent may break)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R9.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R9.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R9 --option <id> --by "Name" --reason "..."`

## R10 · P1-urgent · score 92 · express-jwt@0.1.3: 1 known vulnerability
Status: **pending-approval**

Path: juice-shop@20.4.0-SNAPSHOT > express-jwt@0.1.3
Reachability: imported · Exposure: server

- **R10.a upgrade** ⭐ recommended: Upgrade express-jwt 0.1.3 -> 6.0.0 (major)
  - risk reduction: 1 finding(s), score -92 (expected; confirmed by rescan during validation)
  - compatibility: high (semver major change; 1 source file(s) import express-jwt: lib/insecurity.ts; breaking API changes possible; build + tests must pass before approval is final)
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

## R11 · P1-urgent · score 90 · notevil@1.3.3: 1 known vulnerability
Status: **pending-approval**

Path: juice-shop@20.4.0-SNAPSHOT > notevil@1.3.3
Reachability: imported · Exposure: server

- **R11.a mitigate** ⭐ recommended: No fixed version available: restrict use of the affected function / input, or replace the package
  - risk reduction: 0 finding(s), score -0 (manual mitigation; risk remains until replaced)
  - compatibility: unknown (manual change)
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

## R12 · P1-urgent · score 85 · ws@8.18.0: 1 known vulnerability
Status: **pending-approval**

Path: juice-shop@20.4.0-SNAPSHOT > frontend@20.4.0-SNAPSHOT > ethers@5.8.0 > @ethersproject/providers@5.8.0 > ws@8.18.0
Reachability: parent-imported · Exposure: browser

- **R12.a override** ⭐ recommended: Force ws@8.21.0 with npm overrides
  - risk reduction: 1 finding(s), score -85 (expected; confirmed by rescan during validation)
  - compatibility: high (outside the declared range (@ethersproject/providers declares 8.18.0): parent may break)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R12.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R12.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R12 --option <id> --by "Name" --reason "..."`

## R13 · P1-urgent · score 83 · tar@6.2.1: 8 known vulnerabilities
Status: **pending-approval**

Path: juice-shop@20.4.0-SNAPSHOT > sqlite3@5.1.7 > tar@6.2.1
Reachability: unknown · Exposure: server

- **R13.a upgrade-parent** ⭐ recommended: Upgrade direct dependency sqlite3 5.1.7 -> 6.0.1 (major); sqlite3@6.0.1 requires tar ^7.5.10, which admits a fixed version
  - risk reduction: 8 finding(s), score -610 (expected; the parent upgrade may also change other transitive packages)
  - compatibility: high (semver major change; breaking API changes possible; build + tests must pass before approval is final)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R13.b override**: Force tar@7.5.21 with npm overrides
  - risk reduction: 8 finding(s), score -610 (expected; confirmed by rescan during validation)
  - compatibility: high (outside the declared range (cacache declares ^6.0.2; node-gyp declares ^6.1.2; sqlite3 declares ^6.1.11): parent may break)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R13.c accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R13.d escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R13 --option <id> --by "Name" --reason "..."`

## R14 · P2-high · score 78 · file-type@16.5.4: 1 known vulnerability
Status: **pending-approval**

Path: juice-shop@20.4.0-SNAPSHOT > file-type@16.5.4
Reachability: imported · Exposure: server

- **R14.a upgrade** ⭐ recommended: Upgrade file-type 16.5.4 -> 21.3.1 (major)
  - risk reduction: 1 finding(s), score -78 (expected; confirmed by rescan during validation)
  - compatibility: high (semver major change; 1 source file(s) import file-type: routes/profileImageFileUpload.ts; breaking API changes possible; build + tests must pass before approval is final)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R14.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R14.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R14 --option <id> --by "Name" --reason "..."`

## R15 · P2-high · score 75 · calibreapp/image-actions@main: cicd
Status: **approved** (by TEST-RUN by Claude (not a real human approval): pin third-party action to the commit it runs today; no behaviour change)

Path: —
Reachability: n/a · Exposure: ci-pipeline

- **R15.a pin** ⭐ recommended: Pin calibreapp/image-actions to commit cfe6ba91a2f0 (what 'main' resolves to today)
  - risk reduction: 1 finding(s), score -75 (expected; confirmed by rescan during validation)
  - compatibility: none (identical code to what runs today; only future silent changes are blocked)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R15.b escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R15 --option <id> --by "Name" --reason "..."`

## R16 · P2-high · score 75 · bkimminich/juice-shop@latest: untrusted-image
Status: **pending-approval**

Path: —
Reachability: n/a · Exposure: runtime-image

- **R16.a pin** ⭐ recommended: Pin 'bkimminich/juice-shop' to an explicit version tag + sha256 digest from a trusted registry (digest lookup needs registry access; filled in by the reviewer)
  - risk reduction: 1 finding(s), score -75 (expected; confirmed by rescan during validation)
  - compatibility: low (same image if pinned to the current digest)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R16.b escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R16 --option <id> --by "Name" --reason "..."`

## R17 · P2-high · score 75 · Workflow pipes a downloaded script into a shell
Status: **pending-approval**

Path: —
Reachability: n/a · Exposure: ci-pipeline

- **R17.a escalate** ⭐ recommended: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R17.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R17 --option <id> --by "Name" --reason "..."`

## R18 · P2-high · score 66 · elliptic@6.6.1: 1 known vulnerability
Status: **pending-approval**

Path: juice-shop@20.4.0-SNAPSHOT > frontend@20.4.0-SNAPSHOT > ethers@5.8.0 > @ethersproject/signing-key@5.8.0 > elliptic@6.6.1
Reachability: parent-imported · Exposure: browser

- **R18.a mitigate** ⭐ recommended: No fixed version available: restrict use of the affected function / input, or replace the package
  - risk reduction: 0 finding(s), score -0 (manual mitigation; risk remains until replaced)
  - compatibility: unknown (manual change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R18.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R18.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R18 --option <id> --by "Name" --reason "..."`

## R19 · P2-high · score 60 · base64url@0.0.6: 1 known vulnerability
Status: **pending-approval**

Path: juice-shop@20.4.0-SNAPSHOT > jsonwebtoken@0.4.0 > jws@0.2.6 > base64url@0.0.6
Reachability: parent-imported · Exposure: server

- **R19.a override** ⭐ recommended: Force base64url@3.0.0 with npm overrides
  - risk reduction: 1 finding(s), score -60 (expected; confirmed by rescan during validation)
  - compatibility: high (outside the declared range (jwa declares ~0.0.3; jws declares 0.0.6): parent may break)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R19.b accept**: Accept the risk (requires a written justification and an expiry/review date)
  - risk reduction: 0 finding(s), score -0 (risk accepted, recorded as residual)
  - compatibility: none (no change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)
- **R19.c escalate**: Request security review; keep the component blocked by policy meanwhile
  - risk reduction: 0 finding(s), score -0 (risk unchanged until review decision)
  - compatibility: none (no code change)
  - rollback: the change is a single commit on branch guardian/fix-*; `git revert <commit>` or delete the branch (nothing is merged automatically)

Approve: `python3 -m guardian approve <run> --item R19 --option <id> --by "Name" --reason "..."`
