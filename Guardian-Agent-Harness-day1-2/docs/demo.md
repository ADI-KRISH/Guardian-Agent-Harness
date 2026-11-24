# Three-minute demonstration

1. Start `python3 -m guardian serve` and open http://127.0.0.1:8787.
2. Select **New scan → Try planted demo**. Keep Offline unchecked for live OSV results. Explain that package names and versions are real, but the small inventory is synthetic and the configuration violations are planted.
3. Open **Knowledge graph**. Follow `demo → express → body-parser` or `demo → axios → follow-redirects`. Click a package, then a related finding. Show the exact advisory evidence and available fixed-version boundaries.
4. Toggle **Include evidence & findings** to show package → advisory → evidence-file relationships. Use search, pan and zoom.
5. Open **Findings** and inspect an unpinned workflow action. Show its filename, line, excerpt and risk rationale. Review actions require a human name and written reason; do not claim the tool proved a backdoor.
6. Show **Memory & learning** and its coverage table. Offline/unavailable checks are explicitly partial. Show **Evaluation suite**: 11 planted/clean fixtures.
7. For change tracking, use a disposable copy of `examples/demo`, review and promote its first scan, manually change one package version or integrity field, then rescan that same path. **Changes** shows the diff. A same-version integrity change becomes Critical and blocks baseline promotion until a human reviews it.
8. Export JSON from the dashboard; export CycloneDX or a readable Markdown report through the CLI.

No trusted baseline or human review is seeded automatically. Real repository analysis remains separate from planted fixtures. No fix is automatically applied, installed, merged or deployed.
