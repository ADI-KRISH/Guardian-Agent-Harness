# Investigation: GitHub Action calibreapp/image-actions: branch/unversioned ref 'main' (code changes on every run)

Finding `GRD-46b77d7f63` · rule `CICD-UNPINNED-ACTION` · severity high

## Verified evidence (deterministic sources)

| id | kind | source | fact |
|---|---|---|---|
| F1 | workflow-line | .github/workflows/image_actions.yml:33 | uses: calibreapp/image-actions@main |
| F2 | git-remote | github.com/calibreapp/image-actions | refs/heads/main currently resolves to commit cfe6ba91a2f0e9046d44e2088d002378daeb4a9c (branch: moves with every push) |
| F3 | provenance | workflow | workflow uses 'calibreapp/image-actions@main' without a commit-SHA pin; the code that runs is whatever the ref points to at run time |
| F4 | git-history | git log .github/workflows/image_actions.yml | d6157d3 2026-11-23 Geshna Balaji: Add generated lockfiles (npm install --package-lock-only --legacy-peer-deps, 2026-11-23) |

## Inference (rule-based, NOT verified)

**Verdict:** suspicious (confidence medium)

**Hypothesis:** The workflow runs third-party code from a mutable reference; a compromise of that repository would run in this CI with its secrets.

Rule-based inference from the verified facts; no AI model was used.

Based on facts: F1, F2, F3, F4

**Safe next steps:**
- block the component in policy until reviewed
- restore from the trusted baseline / pin to a reviewed commit
- escalate to security review
