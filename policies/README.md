# Enforced policies

The executable policies live in `guardian/store.py`, `guardian/discovery.py`, `guardian/server.py` and `guardian/osv.py`. This file documents them; it is not a separate policy engine.

- Only explicit review API/CLI calls promote baselines. A named reviewer and written reason are mandatory. Open Critical findings and incomplete inventories block promotion.
- Integrity, typosquat, encoded execution, secret/network combination and bidi findings cannot be suppressed by lessons.
- Other suppressions are exact repository + exact path + rule, expire after 30 days, and require an explicit approval after the regression fixtures pass. Suppressed records remain in the ledger.
- One native scan stage does not establish two independent signals: its findings have Medium confidence.
- Package code, lifecycle hooks, tests and build systems are never executed. Local scans launch no subprocesses. Public GitHub ingestion runs only a fixed `git clone` argument list, with hooks and submodules disabled and Git global/system configuration disabled.
- Input budgets: 12,000 files, 2 MiB per file, 64 MiB total source bytes; symbolic links excluded. Exclusions and size truncation appear as coverage gaps. Archives are not extracted.
- OSV: 8 workers, 2,000 distinct exact versions, 12 pages per query, 12-second HTTP timeout, 8 MiB response bound, 24-hour cache. Failures are not empty successful results.
- Browser writes require a random per-process session token, a localhost Host header, and same-origin Origin when present. No CORS is enabled. Service binds to 127.0.0.1 only.
- SQLite triggers reject modification/deletion of audit records through ordinary database operations. This is not a cryptographic tamper-proof ledger against an administrator who can replace the database.

The native process is not a sandbox and does not implement OS-level egress isolation. Use the documented offline Docker invocation for a network-isolated scan. Online OSV uses a fixed endpoint; deployment-level network policy is required to guarantee an egress allowlist.
