# Remediation plan (recommendations only)

Scan 75a83dd1a8f1 | reachability assessed: True | every item needs human approval

## Critical packages

| # | Package | Action | Clears | Compatibility | Notes |
|---|---|---|---|---|---|
| 1 | tar@6.2.1 (transitive) | override -> 7.5.21 | 12/12 | HIGH | demo: one_fix_many_findings |
| 2 | lodash@2.4.2 (transitive) | override -> 4.17.21 | 4/4 | HIGH | intentionally old in Juice Shop; try parent first: sanitize-html -> 2.18.0 |
| 3 | jsonwebtoken@0.1.0 (transitive) | override -> 9.0.0 | 4/4 | HIGH | intentionally old in Juice Shop; try parent first: express-jwt -> 6.0.0 |
| 4 | jsonwebtoken@0.4.0 (direct) | upgrade -> 9.0.0 | 4/4 | HIGH | intentionally old in Juice Shop; demo: compatibility_trap |
| 5 | crypto-js@3.3.0 (transitive) | override -> 4.2.0 | 2/2 | HIGH | intentionally old in Juice Shop |
| 6 | marsdb@0.6.11 (direct) | escalate_or_accept | 0/1 | n/a | intentionally old in Juice Shop; demo: no_fix_escalate |

## High packages

| # | Package | Action | Clears | Compatibility | Notes |
|---|---|---|---|---|---|
| 1 | sanitize-html@1.4.2 (direct) | upgrade -> 2.18.0 | 10/10 | HIGH | intentionally old in Juice Shop |
| 2 | express-jwt@0.1.3 (direct) | upgrade -> 6.0.0 | 1/1 | HIGH | intentionally old in Juice Shop |
| 3 | moment@2.0.0 (transitive) | override -> 2.29.2 | 3/3 | LOW-MEDIUM | intentionally old in Juice Shop; try parent first: express-jwt -> 6.0.0 |
| 4 | jws@0.2.6 (transitive) | override -> 3.2.3 | 2/2 | HIGH | intentionally old in Juice Shop; try parent first: jsonwebtoken -> 9.0.0 |
| 5 | ws@8.18.0 (transitive) | override -> 8.21.0 | 2/2 | LOW-MEDIUM | demo: hero_fix (safe minor bump) |
| 6 | @cyclonedx/cyclonedx-npm@4.2.1 (direct) | upgrade -> 6.0.0 | 2/2 | HIGH |  |

## Medium packages

| # | Package | Action | Clears | Compatibility | Notes |
|---|---|---|---|---|---|
| 1 | file-type@16.5.4 (direct) | upgrade -> 21.3.1 | 1/1 | HIGH |  |
| 2 | uuid@8.3.2 (transitive) | override -> 11.1.1 | 1/1 | HIGH |  |
| 3 | base64url@0.0.6 (transitive) | override -> 3.0.0 | 1/1 | HIGH | intentionally old in Juice Shop; try parent first: jsonwebtoken -> 9.0.0 |
| 4 | notevil@1.3.3 (direct) | escalate_or_accept | 0/1 | n/a | intentionally old in Juice Shop |
| 5 | hbs@4.4.0 (direct) | escalate_or_accept | 0/1 | n/a | intentionally old in Juice Shop |
| 6 | minimatch@9.0.9 (transitive) | override -> 11.0.1 | 1/1 | HIGH | try parent first: @cyclonedx/cyclonedx-npm -> 6.0.0 |
| 7 | glob@10.5.0 (transitive) | override -> 14.0.2 | 1/1 | HIGH | try parent first: @cyclonedx/cyclonedx-npm -> 6.0.0 |

## Low packages

| # | Package | Action | Clears | Compatibility | Notes |
|---|---|---|---|---|---|
| 1 | messageformat@2.3.0 (transitive) | override -> 3.0.0-beta.0 | 1/1 | HIGH |  |
| 2 | elliptic@6.6.1 (transitive) | escalate_or_accept | 0/1 | n/a |  |
| 3 | @tootallnate/once@1.1.2 (transitive) | override -> 2.0.1 | 1/1 | HIGH |  |

## Non-CVE recommendations

| Action | What | Count |
|---|---|---|
| allowlist_or_review | Install scripts on dependencies | 17 |
| escalate | Heuristic source/backdoor signals | 3 |
| review | Review privileged workflow | 1 |
| pin | Pin GitHub Actions to full commit SHAs | 7 |
| pin | Pin container base images to digests | 5 |
