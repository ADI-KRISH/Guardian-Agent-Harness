# Responsible AI and security note

GuardianAI treats repository contents as untrusted input. No repository scripts, installation hooks or build/test commands run. No LLM is configured; source files are not sent to a model, and `ai_inference` is empty. Online vulnerability queries send only package name, exact version and ecosystem to api.osv.dev. Public GitHub cloning contacts GitHub and never pushes changes.

Local JSON parsing and static pattern matching cannot establish the absence of backdoors. Known advisories cover published knowledge; static signals can have false positives. Check the coverage panel before interpreting an empty finding set. Package-specific fixed-version boundaries are evidence, not a compatibility guarantee.

Human reviews require a name and a reason and are logged. Open Critical findings block baseline promotion. Protected findings cannot be silenced by learning proposals. Other suppressions require exact repository/path/rule scope, an expiry, passing fixture evaluation and explicit approval. Finding severity and original evidence are retained after review.

The API binds to loopback, validates Host, blocks cross-origin mutations, uses a per-process request token, escapes repository text in HTML and sets a restrictive Content Security Policy. These controls are not multi-user authentication. Any trusted local user able to read the service can obtain its session token. Deploying it beyond a workstation requires authentication, authorization, secure transport, resource limits, centralized protected audit storage and appropriate egress policy.

File limits and symlink avoidance bound common static input problems. No archives are extracted, so archive analysis is unavailable. The process is not an OS sandbox; the optional offline Docker invocation isolates the scan network and mounts the target read-only. Container builds and deployment-level limits have not been validated in this environment.

Scan exports may include short source excerpts, paths and package information. Review them before sharing. Source excerpts are kept locally. SQLite audit immutability is enforced through application operations and database triggers, not against a hostile local administrator.
