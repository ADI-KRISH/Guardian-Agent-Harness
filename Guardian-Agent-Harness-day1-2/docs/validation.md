# Validation performed

- Python standard-library unittest suite: 24 tests passed.
- Deterministic regression scoreboard: 11/11 planted and clean cases passed.
- Live OSV demo scan: 9 exact package versions checked; 45 advisory matches and 4 static CI/container findings. Demo data is synthetic and explicitly marked planted.
- Demo graph: 62 entities and 112 typed relationships.
- Browser: overview renders; package node opens relationship details; a body-parser advisory shows `demo → express → body-parser`, OSV evidence and fixed-version boundary; graph nodes support accessible keyboard interaction.
- Local API: Host validation, session-token requirement and cross-origin mutation rejection tested.
- Baseline: same-version hash changes become Critical; open Critical findings prevent promotion; unchanged suspicious source stays visible.
- Learning: protected rules resist suppressions; expired rules do not apply; an approved scoped generated-file lesson reduces noise while the fixture gate remains green.

The Docker recipe and CI workflow were not run in this environment. A full public-repository scan and optional external scanners were not validated; the live network test used the clearly labeled synthetic demo inventory.
