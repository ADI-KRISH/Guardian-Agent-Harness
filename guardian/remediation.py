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
    """Only read unchanged, scan-inventoried files beneath the recorded checkout."""
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
                # Edit an exact requirement only, preserving markers, whitespace and comments.
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
    # 'none' runtime = rescan-only validation (digest/SHA pins) — no build needed, still executable
    plan['execution_ready'] = bool(plan['edits']) and not plan['blockers'] and plan.get('validation_profile',{}).get('runtime') not in ('unsupported',)
    plan['approval_kind'] = 'sandbox_proposal' if plan['diff'] else 'investigation_plan'
    canonical = json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()
    plan['id'] = 'R-' + hashlib.sha256(canonical).hexdigest()[:24]
    return plan
