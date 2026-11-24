# GuardianAI: From Detection to Human Approval (5-Member Team Division)

> **Day 2 Scope:** This guide covers the complete journey **from finding detection up to the human approval gate**:
> 
> `[ Prioritized Risk ] ──► [ Safe Fix Recommendation ] ──► [ Human Approval Gate ]`
> 
> Divided into **5 equal parts** for a team of 5 engineers, including full source code, architecture, and line-by-line explanations.

---

## Team Responsibility Matrix

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                          5-MEMBER PIPELINE DIVISION                                              │
│                                                                                                                  │
│  MEMBER 1: Risk Prioritization ────► MEMBER 2: Candidate Verification ────► MEMBER 3: Manifest & Ref Patching    │
│  • guardian/prioritizer.py          • guardian/candidates.py                • guardian/patching.py               │
│  • Prod vs Dev context              • Registry checks (npm/PyPI)            • guardian/references.py             │
│  • P0–P3 Urgency Tiers              • OSV cross-advisories                  • JSON span mutator & SHA pinning    │
│                                                                                                                  │
│                                           │                                                                      │
│                                           ▼                                                                      │
│                    MEMBER 4: Remediation Plan Brain ────► MEMBER 5: Human Gate & Governance                      │
│                    • guardian/remediation.py             • guardian/store.py & server.py                         │
│                    • SemVer delta & Breaking change      • guardian/static/app.js                                │
│                    • Unified diff & Rollback plan        • Drift preconditions & Audit ledger                    │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

| Member | Focus Area | Files Owned | What They Present to Judges |
|:---:|:---|:---|:---|
| **Member 1** | **Contextual Risk Prioritization** | `guardian/prioritizer.py` | Why CVSS alone fails; how graph topology, production exposure, and threat category map findings to P0–P3. |
| **Member 2** | **Candidate Verification Engine** | `guardian/candidates.py` | Eliminating LLM hallucinations; querying live registries and OSV to find the earliest non-vulnerable version. |
| **Member 3** | **Precision Patching & Reference Pinning** | `guardian/patching.py`<br>`guardian/references.py` | Byte-level JSON AST edits (preserving whitespace/comments); resolving Docker tags and GitHub Actions to immutable SHAs. |
| **Member 4** | **Remediation Brain & Diff Generator** | `guardian/remediation.py` | Assembling the remediation plan: SemVer compatibility (`patch`/`minor`/`major`), unified diffs, and rollback commands. |
| **Member 5** | **Human Governance, Preconditions & UI** | `guardian/store.py`<br>`guardian/server.py`<br>`guardian/static/app.js` | The Human Gate: Drift precondition verification, signed reviewer identity/reason, audit logging, and UI approval form. |

---

# MEMBER 1: Contextual Risk Prioritizer (P0–P3 Urgency Tiers)

### 1. Responsibility
Member 1 explains **Stage 1 of Day 2: Prioritizing Relevant Risks**. Raw CVSS scores are context-blind: a Critical CVE in an offline test linter does not have the same business impact as a High CVE in an internet-facing production server. Member 1 explains how GuardianAI combines graph topology and dependency scope (`dev: true/false`) to classify findings into 4 actionable priority tiers (**P0, P1, P2, P3**).

### 2. Full Source Code (`guardian/prioritizer.py`)
```python
"""Explainable policy priority; inventory membership is not runtime reachability."""
def prioritize(finding, node):
    dev = node.get('dev')
    context = 'development-only inventory' if dev is True else 'production dependency inventory' if dev is False else 'unknown'
    level = finding['risk_level']
    if finding['rule'] in {'integrity-change', 'secret-exfiltration', 'obfuscated-execution'}:
        tier, reason = 'P0', 'Potential integrity or execution compromise requires immediate investigation; malicious intent is not established.'
    elif level == 'Critical':
        tier, reason = 'P1' if dev is True else 'P0', 'Critical advisory or policy signal; development tooling can also affect releases.'
    elif level == 'High':
        tier, reason = 'P2' if dev is True else 'P1', 'High severity signal prioritized conservatively where exposure is unknown.'
    elif level == 'Unknown':
        tier, reason = 'P1', 'Severity is unavailable; investigate before assigning a lower priority.'
    elif level == 'Medium':
        tier, reason = 'P3' if dev is True else 'P2', 'Lower policy severity; review in dependency context.'
    else:
        tier, reason = 'P3', 'Lower policy severity; review in dependency context.'
    return dict(tier=tier, reason=reason, dependency_context=context, direct=node.get('direct'),
                reachability='unknown', exposure='unknown', exploit_availability='unknown',
                confidence=finding.get('confidence', 'Medium'))
```

### 3. Line-by-Line Technical Explanation
- **Lines 3–4 (`dev = node.get('dev')`)**: Reads the dependency graph metadata generated during Day 1 discovery. Identifies whether the component was declared in `dependencies` (production) or `devDependencies` (development only).
- **Lines 6–7 (`P0 Supply Chain Attack Signal`)**: Any finding flagged for malicious backdoor patterns (`integrity-change`, `secret-exfiltration`, `obfuscated-execution`) is immediately escalated to **P0** regardless of CVSS or environment context.
- **Lines 8–9 (`Critical CVEs`)**: If a CVE is Critical and belongs to production, it is **P0** (immediate action). If it belongs to development tooling, it is de-escalated to **P1** (still high urgency, because dev tooling executes during CI/CD build scripts and could compromise build artifacts).
- **Lines 10–11 (`High CVEs`)**: High CVEs in production are prioritized as **P1**, while High CVEs in dev dependencies become **P2**.
- **Lines 12–13 (`Unknown Severity`)**: If an advisory lacks CVSS data, Guardian prioritizes conservatively at **P1** rather than ignoring it.
- **Lines 14–15 (`Medium/Low CVEs`)**: Medium in production is **P2**; dev-only or Low severity is **P3** (deferred).
- **Lines 16–18 (`Intellectual Honesty`)**: Explicitly sets `reachability='unknown'`. Static analysis observes file presence, but cannot honestly guarantee dynamic execution without a sandbox; stating this builds trust with evaluators.

---

# MEMBER 2: Candidate Verification & OSV Boundary Checker

### 1. Responsibility
Member 2 explains **how safe upgrade targets are identified**. Many automated remediation tools use LLMs to invent version numbers or blindly propose the latest release (which often breaks compatibility or carries new CVEs). Member 2 shows how Guardian deterministically selects the **earliest safe version** by querying live package registries and cross-checking against the OSV advisory database.

### 2. Full Source Code (`guardian/candidates.py`)
```python
"""Validate advisory candidates against public registries and OSV, not example versions."""
from urllib.parse import quote
from .references import metadata
from . import osv


def choose(node, finding, store, parse_version):
    current = parse_version(node.get('version'))
    if current is None: raise ValueError('Version ordering is unsupported for this ecosystem/version')
    advisories, status = osv.query(node, store)
    if status not in ('live', 'cached'): raise ValueError('Advisory lookup unavailable')
    fixes = set()
    matched = False
    ids = {finding.get('advisory'), *finding.get('aliases', [])} - {None}
    for advisory in advisories:
        if advisory.get('withdrawn'): continue
        if ids & {advisory['id'], *advisory.get('aliases', [])}: matched = True
        for affected in advisory.get('affected', []):
            package = affected.get('package', {})
            if package.get('name') != node['name'] or package.get('ecosystem') != node['ecosystem']: continue
            for interval in affected.get('ranges', []):
                if interval.get('type') == 'GIT': continue
                fixes.update(e['fixed'] for e in interval.get('events', []) if e.get('fixed'))
    if not matched: raise ValueError('Original advisory is no longer matched; rescan before recommending a change')
    
    # Also evaluate the current stable release from the registry
    if node['ecosystem'] in ('npm','PyPI'):
        latest_url = ('https://registry.npmjs.org/'+quote(node['name'],safe='')+'/latest' if node['ecosystem']=='npm' else 'https://pypi.org/pypi/'+quote(node['name'],safe='')+'/json')
        try:
            latest, _ = metadata(latest_url)
            latest_version = latest.get('version') if node['ecosystem']=='npm' else latest.get('info',{}).get('version')
            if latest_version: fixes.add(latest_version)
        except (OSError,ValueError):
            pass

    # Sort strictly by SemVer order greater than current
    candidates = sorted((v for v in fixes if parse_version(v) is not None and parse_version(v) > current), key=parse_version)
    attempts = []
    for target in candidates[:12]:
        if node['ecosystem'] == 'npm':
            url = 'https://registry.npmjs.org/'+quote(node['name'], safe='')+'/'+quote(target, safe='')
        elif node['ecosystem'] == 'PyPI':
            url = 'https://pypi.org/pypi/'+quote(node['name'], safe='')+'/'+quote(target, safe='')+'/json'
        else: raise ValueError('Registry verification adapter is not implemented for this ecosystem')
        package, _ = metadata(url)
        if node['ecosystem'] == 'npm':
            exists = package.get('version') == target and not package.get('deprecated')
        else:
            exists = package.get('info', {}).get('version') == target and any(not f.get('yanked') for f in package.get('urls', []))
        if not exists:
            attempts.append({'version':target,'result':'release unavailable, deprecated or yanked'}); continue
        
        # Verify candidate in OSV: does this candidate introduce another CVE?
        remaining, candidate_status = osv.query(dict(node, version=target), store)
        remaining = [a for a in remaining if not a.get('withdrawn')]
        attempts.append({'version':target,'remaining_advisories':[a['id'] for a in remaining]})
        if candidate_status in ('live', 'cached') and not remaining:
            return target, {'registry':url, 'advisories':candidate_status, 'result':'No known advisories returned for candidate identity; runtime compatibility unverified', 'attempts':attempts}
    raise ValueError('No verified candidate found among advisory boundaries and current stable release; attempts: '+str(attempts))
```

### 3. Line-by-Line Technical Explanation
- **Lines 8–12**: Reads the current package version and queries the local SQLite OSV cache.
- **Lines 16–25**: Iterates through the advisory's `affected[].ranges[].events` and collects every version marked with `fixed` (e.g. `4.0.14`, `4.7.7`, `4.7.10`).
- **Lines 28–35**: Queries `registry.npmjs.org/<package>/latest` or PyPI JSON to check if the upstream maintainer released an even newer stable version.
- **Line 36 (`candidates = sorted(...)`)**: Filters out any version less than or equal to the current version, sorting strictly in ascending SemVer order (preferring the lowest version bump to minimize API breakage).
- **Lines 38–50 (`Registry Live Verification`)**: Contacts the package registry to ensure the candidate version actually exists on the public registry, is not marked `deprecated`, and has not been `yanked`.
- **Lines 51–55 (`Cross-Advisory Verification`)**: Queries OSV for the *new* target version. If `4.7.7` fixes vulnerability A but still contains vulnerability B, it is rejected and logged in `attempts`. The engine advances until it finds a release with **zero remaining advisories**.

---

# MEMBER 3: AST/Span-Based Manifest Patching & Non-CVE Reference Pinning

### 1. Responsibility
Member 3 explains **the mechanics of generating safe code edits**:
1. **Manifest Patching (`patching.py`)**: How `package.json` is modified with byte-level precision without mangling developer formatting or removing comments.
2. **Reference Pinning (`references.py`)**: How non-CVE supply chain threats (like unpinned GitHub Actions and floating Docker tags) are transformed into immutable, tamper-proof commit SHAs and container digests.

### 2. Full Source Code: Manifest Mutator (`guardian/patching.py`)
```python
"""JSON value edits preserve unrelated bytes, indentation and comments in other files."""
import json


def json_spans(text):
    decoder = json.JSONDecoder()
    spans = {}
    def ws(i):
        while i < len(text) and text[i].isspace(): i += 1
        return i
    def parse(i, path):
        i = ws(i); start = i
        if text[i] == '{':
            i = ws(i + 1); keys = set()
            while text[i] != '}':
                key, end = decoder.raw_decode(text, i)
                if not isinstance(key, str) or key in keys: raise ValueError('Ambiguous JSON keys')
                keys.add(key); i = ws(end)
                if text[i] != ':': raise ValueError('Invalid JSON object')
                i = ws(parse(i + 1, path + (key,)))
                if text[i] == '}': break
                if text[i] != ',': raise ValueError('Invalid JSON separator')
                i = ws(i + 1)
            end = i + 1
        else:
            _, end = decoder.raw_decode(text, i)
        spans[path] = (start, end)
        return end
    try:
        end = parse(0, ())
        if text[end:].strip(): raise ValueError('Trailing JSON data')
    except (IndexError, json.JSONDecodeError) as exc:
        raise ValueError('Invalid JSON document') from exc
    return spans


def replace_values(text, replacements):
    spans = json_spans(text)
    edits = []
    for path, value in replacements.items():
        if path not in spans: raise ValueError('Dependency declaration not found')
        start, end = spans[path]
        edits.append((start, end, json.dumps(value, ensure_ascii=False)))
    for start, end, value in sorted(edits, reverse=True):
        text = text[:start] + value + text[end:]
    json.loads(text)
    return text


def add_field(text, path, name, value):
    spans = json_spans(text)
    if path + (name,) in spans: return replace_values(text,{path+(name,):value})
    if path not in spans: raise ValueError('JSON object not found')
    start,end = spans[path]
    obj = json.loads(text[start:end])
    if not isinstance(obj,dict): raise ValueError('Expected JSON object')
    insertion = (',' if obj else '') + '\n' + '  '*(len(path)+1) + json.dumps(name) + ': ' + json.dumps(value,ensure_ascii=False) + '\n' + '  '*len(path)
    return text[:end-1] + insertion + text[end-1:]
```

### 3. Full Source Code: Non-CVE Reference Pinning (`guardian/references.py`)
```python
"""Bounded public metadata lookups; never execute repository code."""
import json
import re
import urllib.parse
import urllib.request


def metadata(url, headers=None):
    request = urllib.request.Request(url, headers={'User-Agent': 'GuardianAI/0.1', **(headers or {})})
    with urllib.request.urlopen(request, timeout=8) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError('Registry metadata exceeded budget')
        return json.loads(raw), response.headers


def resolve(rule, line):
    if rule == 'unpinned-action':
        match = re.search(r'uses:\s*[\'\"]?([\w.-]+/[\w./-]+)@([\w./-]+)', line)
        if not match: raise ValueError('Unsupported action reference')
        action, ref = match.groups()
        owner, repo = action.split('/')[:2]
        url = f'https://api.github.com/repos/{owner}/{repo}/commits/{urllib.parse.quote(ref, safe="")}'
        data, _ = metadata(url)
        sha = data.get('sha', '')
        if not re.fullmatch('[0-9a-f]{40}', sha): raise ValueError('Invalid commit SHA returned')
        return action+'@'+ref, action+'@'+sha, url
    match = re.match(r'\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)', line, re.I)
    if not match: raise ValueError('Unsupported Docker FROM reference')
    original = match.group(1)
    if '$' in original or '@' in original: raise ValueError('Dynamic or already pinned image requires manual review')
    image, sep, tag = original.rpartition(':')
    if not sep: image, tag = original, 'latest'
    image = image.removeprefix('docker.io/').removeprefix('index.docker.io/')
    if '/' not in image: image = 'library/'+image
    if not re.fullmatch(r'[a-z0-9_-]+/[a-z0-9._-]+', image):
        raise ValueError('Automatic lookup currently supports public Docker Hub images only')
    query = urllib.parse.urlencode({'service':'registry.docker.io', 'scope':'repository:'+image+':pull'})
    auth, _ = metadata('https://auth.docker.io/token?'+query)
    url = 'https://registry-1.docker.io/v2/'+image+'/manifests/'+urllib.parse.quote(tag, safe='')
    _, headers = metadata(url, {'Authorization':'Bearer '+auth['token'], 'Accept':'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'})
    digest = headers.get('Docker-Content-Digest', '')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest): raise ValueError('Registry did not return a valid immutable digest')
    return original, original+'@'+digest, url
```

### 4. Line-by-Line Technical Explanation
- **`json_spans(text)`**: Rather than deserializing JSON with `json.loads` (which destroys key order and comments), it uses a raw scanner to record byte coordinates `(start, end)` for every key and value.
- **`replace_values(...)`**: Replaces only the exact version bytes in reverse order, ensuring git diffs only touch 1 line.
- **`add_field(...)`**: Appends the `"overrides"` block cleanly before the final closing brace.
- **`resolve('unpinned-action', line)`**: Extracts GitHub Actions like `actions/checkout@v2`, queries the GitHub Commits REST API, and resolves `@v2` into an immutable 40-character commit SHA (`@b4ffde...`).
- **`resolve('floating-image', line)`**: Extracts `FROM node:20`, calls the Docker Registry v2 manifests endpoint, and resolves `:20` into an immutable digest (`@sha256:1a82...`).

---

# MEMBER 4: Remediation Brain & Unified Diff Generator

### 1. Responsibility
Member 4 explains **`guardian/remediation.py`**, the central brain of Day 2. Member 4 demonstrates how candidate lookups, SemVer compatibility calculations, unified diffs, preconditions, and rollback plans are combined into a canonical proposal (`R-...`).

### 2. Full Source Code (`guardian/remediation.py`)
```python
"""Reviewable proposals only. No patch application, installs, or repository execution."""
import difflib
import hashlib
import json
import re
from pathlib import Path
from .prioritizer import prioritize


def version(value):
    match = re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', str(value))
    return tuple(map(int, match.groups())) if match else None


def compatibility(current, target):
    a, b = version(current), version(target)
    if not a or not b: return 'unknown'
    if a[0] != b[0]: return 'major'
    if a[0] == 0: return 'pre-1.0'
    return 'minor' if a[1] != b[1] else 'patch'


def source(scan, name):
    info = scan.get('files', {}).get(name)
    root = scan.get('source_root', scan.get('repo', ''))
    if not info or info.get('generated') or '://' in root: return None
    root = Path(root).resolve()
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts: return None
    path = root / relative
    if any(p.is_symlink() for p in [path, *path.parents] if p != root and root in p.parents): return None
    if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024: return None
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != info.get('hash'): return None
    try: return raw.decode('utf-8')
    except UnicodeDecodeError: return None


def propose(scan, finding, store=None):
    node = next((n for n in scan['graph']['nodes'] if n['id'] == finding['component']), {})
    plan = dict(scan_id=scan['id'], finding_id=finding['id'], strategy='escalate',
                action='Investigate evidence and select a reviewed change', target_file=finding.get('file'),
                current_version=node.get('version'), target_version=None, diff='', compatibility='unknown',
                compatibility_warning='Compatibility has not been tested. Review and validation are required.',
                priority=prioritize(finding, node), evidence=finding.get('verified_evidence', []),
                inference=finding.get('ai_inference', []), blockers=[], preconditions={},
                expected_risk_reduction='Unverified: reassess the target finding after build, tests and rescan. No score reduction is claimed.',
                rollback='After implementation, revert only the approved change using its recorded patch/commit. Preserve pre-existing edits; do not reset files to HEAD.',
                validation_status='not_run', status='pending', executable=False, edits=[], generator_version=2)
    rule = finding['rule']
    if rule == 'known-vulnerability':
        plan.update(strategy='upgrade', action='Review an advisory fixed-version candidate')
        current = version(node.get('version'))
        candidates = sorted({v for v in finding.get('fix_versions', []) if version(v) and current and version(v) > current}, key=version)
        if store is not None and node.get('ecosystem') in ('npm', 'PyPI'):
            try:
                from .candidates import choose
                candidate, verification = choose(node, finding, store, version)
                candidates = [candidate]
                plan['candidate_verification'] = verification
            except (OSError, ValueError, KeyError, TypeError) as exc:
                candidates = []
                plan['blockers'].append('Candidate verification unavailable: '+str(exc)[:300])
        if candidates and node.get('ecosystem') == 'npm':
            target = candidates[0]
            plan.update(target_package=node.get('name'), target_version=target, compatibility=compatibility(node['version'], target))
            plan['compatibility_warning'] = f"{plan['compatibility']} update: SemVer is a compatibility signal, not a guarantee. Confirm advisory branch applicability and all other advisories; regenerate the lockfile and run tests after approval."
            name = node.get('source_manifest') or str(Path(node.get('file', '')).with_name('package.json'))
            plan['target_file'] = name
            text = source(scan, name)
            if text is not None:
                try:
                    manifest = json.loads(text)
                    from .patching import replace_values
                    from .resolver import sanitized_manifest
                    sanitized_manifest(manifest)
                    replacements = {}
                    for section in ('dependencies', 'devDependencies', 'optionalDependencies'):
                        if node['name'] in manifest.get(section, {}):
                            replacements[(section, node['name'])] = target
                    if replacements:
                        updated = replace_values(text, replacements)
                    elif not node.get('direct'):
                        from .patching import add_field
                        if 'overrides' in manifest:
                            overrides = manifest['overrides']
                            if not isinstance(overrides,dict) or any(not isinstance(v,str) for v in overrides.values()):
                                raise ValueError('Nested overrides need a reviewed migration')
                            updated = add_field(text, ('overrides',), node['name'], target)
                        else:
                            updated = add_field(text, (), 'overrides', {node['name']:target})
                        plan['compatibility_warning'] += ' Transitive override may violate parent compatibility expectations and affects all matching installations; parent behavior must be tested.'
                        plan['transitive_override'] = True
                    else: raise ValueError('Dependency declaration not found')
                    plan['edits'] = [{'file':name, 'before_hash':scan['files'][name]['hash'], 'after':updated}]
                    plan['diff'] = ''.join(difflib.unified_diff(text.splitlines(True), updated.splitlines(True), fromfile='a/'+name, tofile='b/'+name))
                    plan['preconditions'][name] = scan['files'][name]['hash']
                    lock_name = node.get('file')
                    if lock_name in scan['files'] and not scan['files'][lock_name].get('generated'):
                        if source(scan, lock_name) is None:
                            plan['diff'] = ''
                            raise ValueError('Scanned dependency file changed; rescan before proposing an upgrade')
                        plan['preconditions'][lock_name] = scan['files'][lock_name]['hash']
                    plan['action'] = 'Propose exact version in manifest; lockfile update still required'
                except (ValueError, TypeError, AttributeError) as exc:
                    plan['blockers'].append(str(exc))
            else:
                plan['blockers'].append('Transitive dependency or unchanged manifest unavailable: select a parent upgrade or reviewed override; no lockfile-only edit generated.')
        elif candidates and node.get('ecosystem') == 'PyPI' and Path(node.get('file','')).name.startswith('requirements'):
            name = node['file']; text = source(scan, name); target = candidates[0]
            if text is not None:
                norm = lambda value: re.sub(r'[-_.]+','-',value).lower()
                pattern = re.compile(r'(?m)^(\s*)([\w.-]+)(\[[^]\n]+\])?(\s*==\s*)([\w.+!-]+)')
                matches = [m for m in pattern.finditer(text) if norm(m[2]) == norm(node['name']) and m[5] == node['version']]
                if len(matches) == 1 and '--hash' not in text:
                    match = matches[0]; updated = text[:match.start(5)] + target + text[match.end(5):]
                    plan.update(target_file=name, target_version=target, compatibility=compatibility(node['version'],target))
                    plan['edits'] = [{'file':name,'before_hash':scan['files'][name]['hash'],'after':updated}]
                    plan['preconditions'][name] = scan['files'][name]['hash']
                    plan['diff'] = ''.join(difflib.unified_diff(text.splitlines(True),updated.splitlines(True),fromfile='a/'+name,tofile='b/'+name))
                    plan['action'] = 'Upgrade exact Python requirement; resolve and validate in sandbox'
                else: plan['blockers'].append('Ambiguous or hash-pinned Python requirement requires manual review')
            else: plan['blockers'].append('Unchanged Python requirements file unavailable')
        else:
            plan['blockers'].append('No supported stable upgrade candidate. Inspect advisory ranges and ecosystem-specific version ordering manually.')
    elif rule in {'floating-image', 'unpinned-action'}:
        plan.update(strategy='pin_digest' if rule == 'floating-image' else 'pin_sha',
                    action='Resolve and verify an immutable image digest' if rule == 'floating-image' else 'Resolve and verify the action release commit SHA')
        text = source(scan, finding['file'])
        try:
            if text is None: raise ValueError('Unchanged scanned source is unavailable; rescan the checkout')
            from .references import resolve
            lines = text.splitlines(True)
            index = finding['line'] - 1
            old, new, reference = resolve(rule, lines[index])
            lines[index] = lines[index].replace(old, new, 1)
            plan['diff'] = ''.join(difflib.unified_diff(text.splitlines(True), lines, fromfile='a/'+finding['file'], tofile='b/'+finding['file']))
            plan['edits'] = [{'file':finding['file'],'before_hash':scan['files'][finding['file']]['hash'],'after':''.join(lines)}]
            plan['preconditions'][finding['file']] = scan['files'][finding['file']]['hash']
            plan['target_version'] = new.split('@')[-1]
            plan['reference_source'] = reference
            plan['compatibility_warning'] = 'Pins the currently resolved reference. Immutability does not establish publisher trust or absence of vulnerabilities. Validate platform and behavior after approval.'
            plan['action'] = 'Review immutable reference resolved from public provider metadata'
        except (OSError, ValueError, KeyError, IndexError) as exc:
            plan['blockers'].append('Immutable reference lookup unavailable: '+str(exc)[:250])
    elif rule in {'privileged-workflow', 'root-container', 'privileged-container', 'docker-socket'}:
        plan.update(strategy='harden', action='Review required privileges and reduce to least privilege')
        plan['blockers'].append('Configuration needs contextual review before a precise least-privilege patch can be selected.')
    elif rule in {'secret-exfiltration', 'obfuscated-execution', 'integrity-change', 'typosquat', 'install-script', 'download-execute'}:
        plan.update(strategy='investigate_then_block', action='Investigate the signal; if confirmed, block or replace the affected component')
        plan['blockers'].append('Static evidence does not establish malicious intent. Removal requires dependency and behavior review.')
    else:
        plan['blockers'].append('Human investigation is required to choose a supported change.')
    if not plan['diff']:
        plan['edits'] = []
    if plan['edits']:
        from .validation_profile import profile
        try:
            plan['validation_profile'] = profile(scan, plan, source)
        except (ValueError, TypeError) as exc:
            plan['validation_profile'] = {'runtime':'unsupported', 'commands':[], 'reason':str(exc)}
    plan['execution_ready'] = bool(plan['edits']) and not plan['blockers'] and plan.get('validation_profile',{}).get('runtime') not in ('unsupported',)
    plan['approval_kind'] = 'sandbox_proposal' if plan['diff'] else 'investigation_plan'
    canonical = json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()
    plan['id'] = 'R-' + hashlib.sha256(canonical).hexdigest()[:24]
    return plan
```

### 3. Line-by-Line Technical Explanation
- **Lines 15–21 (`compatibility()`)**: Computes the SemVer delta between current and target version:
  - `patch` (e.g. `1.0.1` $\rightarrow$ `1.0.2`): Safe bugfix, lowest risk.
  - `minor` (e.g. `1.1.0` $\rightarrow$ `1.2.0`): Backward-compatible new features.
  - `major` (e.g. `4.0.0` $\rightarrow$ `5.0.0`): Breaking changes possible.
- **Lines 23–37 (`source()`)**: Reads the file directly from the scanned repo, verifying its SHA-256 hash matches the inventory. If the file was modified on disk, remediation aborts to avoid patching stale code.
- **Lines 78–94 (`Direct vs Transitive Overrides`)**:
  - If direct dependency: updates `dependencies[pkg] = target`.
  - If transitive dependency: adds an `"overrides": {pkg: target}` entry so npm resolves the secure version tree-wide.
- **Line 97 (`difflib.unified_diff`)**: Generates standard unified diff lines (`--- a/package.json +++ b/package.json`) so the reviewer sees the exact patch.
- **Line 98 (`preconditions`)**: Records the SHA-256 hash of the target manifest before modification.
- **Lines 167–168 (`plan['id']`)**: Computes a deterministic SHA-256 hash of the canonical plan JSON to generate its unique ID (`R-...`).

---

# MEMBER 5: Human Gate, Precondition Integrity & Decision UI

### 1. Responsibility
Member 5 explains **Stage 3: The Human Approval Gate**. Member 5 demonstrates the security controls that enforce human-in-the-loop governance:
1. **Precondition Integrity**: Before a human decision is recorded, the engine re-checks that files have not drifted on disk.
2. **Reviewer Identity & Rationale**: The engine strictly rejects anonymous or reason-less approvals.
3. **Immutable Audit Ledger**: Decisions are permanently written to SQLite with timestamps and actor names.
4. **Interactive UI Approval Form**: Reviewers inspect the proposed diff, SemVer impact, and candidate checks in the UI drawer before submitting approval.

### 2. Full Source Code: Preconditions & Audit Ledger (`guardian/store.py`)
```python
    def recommend(self, scan_id, finding_id):
        from .remediation import propose
        scan = self.get(scan_id)
        finding = next((f for f in scan['findings'] if f['id'] == finding_id), None)
        if not finding:
            raise ValueError('Finding not found')
        plan = propose(scan, finding, self)
        with self.connect() as db:
            inserted = db.execute('INSERT OR IGNORE INTO remediation_plans VALUES(?,?,?)', (plan['id'], scan_id, json.dumps(plan))).rowcount
            if inserted:
                db.execute('INSERT INTO audit(scan_id,actor,decision,reason,created) VALUES(?,?,?,?,?)', (scan_id, 'Remediation engine', 'Proposed '+plan['id'], finding_id+'; '+plan['action'], now()))
        return next(p for p in self.recommendations(scan_id) if p['id'] == plan['id'])

    def decide_remediation(self, plan_id, status, actor, reason):
        self.identity(actor, reason)
        if status not in ('approved', 'rejected'):
            raise ValueError('Decision must be approved or rejected')
        with self.connect() as db:
            row = db.execute('SELECT data FROM remediation_plans WHERE id=?', (plan_id,)).fetchone()
        if not row:
            raise ValueError('Remediation plan not found')
        plan = json.loads(row['data'])
        if status == 'approved':
            from .remediation import source
            scan = self.get(plan['scan_id'])
            # Drift Precondition Check: Fail if repo files changed since scanning
            for name, digest in plan['preconditions'].items():
                if scan['files'].get(name, {}).get('hash') != digest or source(scan, name) is None:
                    raise ValueError('Source changed since scanning. Rescan and generate a new recommendation.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM remediation_decisions WHERE plan_id=?', (plan_id,)).fetchone():
                raise ValueError('This plan already has a final human decision')
            created = now()
            db.execute('INSERT INTO remediation_decisions VALUES(?,?,?,?,?)', (plan_id, status, actor, reason, created))
            db.execute('INSERT INTO audit(scan_id,actor,decision,reason,created) VALUES(?,?,?,?,?)', (plan['scan_id'], actor, plan_id+': '+status, plan['finding_id']+'; '+reason+'; decision only; validation not run', created))
        return dict(plan_id=plan_id, status=status, validation_status='not_run', applied=False)

    @staticmethod
    def identity(actor, reason):
        if not str(actor).strip() or not str(reason).strip():
            raise ValueError('A reviewer name and written reason are required')
```

### 3. Full Source Code: REST API Endpoints (`guardian/server.py`)
```python
                if path=='/api/remediation/recommend':
                    return self.send(200,store.recommend(data['scan_id'],data['finding_id']))
                if path in ('/api/remediation/decision','/api/remediation/validate'):
                    if path.endswith('/decision'):
                        result=store.decide_remediation(data['plan_id'],data['status'],data.get('actor',''),data.get('reason',''))
                        if data['status']!='approved' or not data.get('validate'):
                            return self.send(200,result)
                    validation_id=store.begin_validation(data['plan_id'])
                    def validation_work():
                        from .validator import validate
                        validate(store,data['plan_id'],validation_id,lambda stage:store.validation_progress(validation_id,stage))
                    threading.Thread(target=validation_work,daemon=True).start()
                    return self.send(202,{'validation_id':validation_id,'status':'running','applied':False})
```

### 4. Full Source Code: UI Approval Component (`guardian/static/app.js`)
```javascript
function renderRemediation(plan) {
  const container = $('#remediation-plan');
  if (!container) return;
  container.innerHTML = `<h3>${esc(plan.action)}</h3>
<p>${badge(plan.status)} · ${esc(plan.approval_kind)} · Validation: ${esc(plan.validation_status || 'not_run')}</p>
<p><strong>Target:</strong> ${esc(plan.target_file || 'Requires investigation')}<br>
<strong>Version:</strong> ${esc(plan.current_version || '—')} → ${esc(plan.target_version || 'Unresolved')}</p>
<h3>Compatibility: ${esc(plan.compatibility)}</h3><p>${esc(plan.compatibility_warning)}</p>
${plan.blockers.length ? `<h3>Required investigation</h3><ul>${plan.blockers.map(b => `<li>${esc(b)}</li>`).join('')}</ul>` : ''}
<h3>Proposed diff</h3><pre>${esc(plan.diff || 'No precise patch available. Approval covers investigation only.')}</pre>
<h3>Expected risk reduction</h3><p>${esc(plan.expected_risk_reduction)}</p>
<h3>Rollback guidance</h3><p>${esc(plan.rollback)}</p>
<p>Plan ${esc(plan.id)}. The original repository is never modified by validation.</p>
${plan.candidate_verification ? `<h3>Candidate checks</h3><pre>${esc(JSON.stringify(plan.candidate_verification, null, 2))}</pre>` : ''}
${plan.validation_profile ? `<h3>Sandbox execution plan</h3><p>${esc(plan.validation_profile.network_policy || plan.validation_profile.reason)}</p><pre>${esc(JSON.stringify(plan.validation_profile.commands, null, 2))}</pre><p>Checks not configured: ${esc((plan.validation_profile.missing_checks || []).join(', ') || 'None')}</p>` : ''}
<div id="validation-result"></div>
${plan.status === 'pending' ? `<form id="remediation-decision">
<label>Reviewer name<input id="remediation-actor" required maxlength="200" value="Security Engineer"></label>
<label>Decision reason<textarea id="remediation-reason" required maxlength="4000">Approved proposed fix for automated sandbox validation and rescan</textarea></label>
<button class="primary" type="submit" value="approved">${plan.execution_ready ? 'Approve & validate in sandbox' : 'Approve investigation plan'}</button>
<button class="secondary" type="submit" value="rejected">Reject</button>
</form>` : `<p><strong>Decision:</strong> ${esc(plan.status.toUpperCase())} by ${esc(plan.decision?.actor)} (${esc(plan.decision?.created)})<br><em>${esc(plan.decision?.reason)}</em></p>`}`;
```

### 5. Line-by-Line Technical Explanation
- **`store.py:decide_remediation()`**:
  - **Drift Protection**: Compares `scan['files'][name]['hash']` against `plan['preconditions'][name]`. If a developer changed `package.json` after the scan was taken, the approval is rejected with: *"Source changed since scanning. Rescan and generate a new recommendation."*
  - **Single Final Decision**: Enforces `SELECT 1 FROM remediation_decisions WHERE plan_id=?`. Once a human decision is recorded, it cannot be overridden or tampered with.
  - **Audit Logging**: Inserts an immutable row into the `audit` table capturing timestamp, reviewer name (`actor`), plan ID, status (`approved` or `rejected`), and written justification (`reason`).
- **`server.py`**:
  - `POST /api/remediation/decision` checks same-origin headers and the session token (`X-Guardian-Token`), validates the JSON body, and delegates validation to a background thread (`validation_work()`).
- **`app.js`**:
  - Renders the human approval form with `remediation-actor` and `remediation-reason`.
  - Disables action buttons during transit to prevent double-submits.
  - When approved, immediately initiates live polling to track sandbox execution.

---

## Complete Data Artifact (The Approved Plan Object)

```json
{
  "id": "R-2cd016d045e822a066b62c02",
  "scan_id": "416e303805a5",
  "finding_id": "G-0a548fc296f9-GHSA-765h-qjxv-5f44",
  "strategy": "upgrade",
  "action": "Propose exact version in manifest; lockfile update still required",
  "target_file": "package.json",
  "target_package": "handlebars",
  "current_version": "4.0.11",
  "target_version": "4.7.10",
  "compatibility": "minor",
  "compatibility_warning": "minor update: SemVer is a compatibility signal, not a guarantee. Confirm advisory branch applicability and all other advisories; regenerate the lockfile and run tests after approval.",
  "diff": "--- a/package.json\n+++ b/package.json\n@@ -54,4 +54,6 @@\n  \"license\": \"Apache-2.0\"\n+,\n+ \"overrides\": {\"handlebars\": \"4.7.10\"}\n }\n",
  "priority": {
    "tier": "P0",
    "dependency_context": "production dependency inventory",
    "direct": false,
    "confidence": "High",
    "reason": "Critical advisory or policy signal; development tooling can also affect releases."
  },
  "candidate_verification": {
    "registry": "https://registry.npmjs.org/handlebars/4.7.10",
    "advisories": "cached",
    "result": "No known advisories returned for candidate identity; runtime compatibility unverified"
  },
  "preconditions": {
    "package.json": "9f83a84ec012891bb...sha256"
  },
  "rollback": "After implementation, revert only the approved change using its recorded patch/commit. Preserve pre-existing edits; do not reset files to HEAD.",
  "status": "approved",
  "decision": {
    "actor": "Security Engineer",
    "reason": "Approved proposed fix for automated sandbox validation and rescan",
    "created": "2026-11-24T05:45:00Z"
  },
  "execution_ready": true,
  "approval_kind": "sandbox_proposal"
}
```
