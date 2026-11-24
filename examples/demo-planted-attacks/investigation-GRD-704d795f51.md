# Investigation: Integrity hash changed for unchanged version lodash@4.17.15

Finding `GRD-704d795f51` · rule `CHANGE-INTEGRITY` · severity critical

## Verified evidence (deterministic sources)

| id | kind | source | fact |
|---|---|---|---|
| F1 | sbom-diff | demo/baseline/package-lock.json | baseline integrity: sha512-8xOcRHvCjnocdS5cpwXQXVzmmh5e5+saE2QGoeQmb... |
| F2 | lockfile-entry | package-lock.json:node_modules/lodash | current integrity: sha512-WJAEnrj+gB2oUrTvMs/hGDhnO9wWZDAUwbYwgNb3E... |
| F3 | dependency-path | dependency graph | shop-api@1.4.0 > lodash@4.17.15 |
| F4 | baseline-diff | baseline vs current | version unchanged: 4.17.15 |
| F5 | baseline-diff | baseline vs current | integrity: sha512-8xOcRHvCjnocdS5cpwXQXVzmmh5e5+saE2QGoeQmbKmRS6J3VQppPOIt0MnmE+4xlZoumy0GPG0D0MVIQbN -> sha512-WJAEnrj+gB2oUrTvMs/hGDhnO9wWZDAUwbYwgNb3EUuzGyEBdHyxxUQKN2kqJqY/EEWBKv71jtRWGlRR1Nt |
| F6 | manifest | package.json | declared as lodash: 4.17.15 (dependencies) |
| F7 | registry | registry.npmjs.org | latest dist-tag: 4.18.1; 117 versions published |
| F8 | registry | registry.npmjs.org | package first published 2012-04-23 |
| F9 | registry | registry.npmjs.org | version 4.17.15 published 2019-07-19 |
| F10 | provenance | registry.npmjs.org | no npm provenance attestation for 4.17.15 (build origin not verifiable) |
| F11 | registry | registry.npmjs.org | version published by npm user 'jdalton' |
| F12 | provenance | registry.npmjs.org | source repository: git+https://github.com/lodash/lodash.git |
| F13 | git-history | git log package-lock.json | no history available (shallow clone or untracked file) |

## Inference (rule-based, NOT verified)

**Verdict:** suspicious (confidence medium)

**Hypothesis:** The same version now has different bytes than before, which points to lockfile tampering or a compromised mirror.

Rule-based inference from the verified facts; no AI model was used.

Based on facts: F1, F2, F3, F4, F5, F6

**Safe next steps:**
- block the component in policy until reviewed
- restore from the trusted baseline / pin to a reviewed commit
- escalate to security review
