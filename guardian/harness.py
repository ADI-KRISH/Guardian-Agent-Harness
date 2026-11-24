"""Read-only adapter for the ZIP harness's no-fix investigator and patch author."""
import difflib
import hashlib
import json
import os
import re
from pathlib import Path

from .harness_prompts import PATCH_SYSTEM, _chat_json, feature_tokens


class ModelReply(str):
    """Text with provenance retained by the proposal adapter."""


def chat(system, user):
    from .ai import local_request, status
    available = status()
    models = available.get('models', [])
    model = os.environ.get('GUARDIAN_OLLAMA_MODEL') or next((m['name'] for m in models if m['name'].startswith('mistral')), models[0]['name'] if models else '')
    if not available.get('available') or not any(m['name'] == model for m in models):
        raise ValueError('No installed local model available. Start Ollama and configure GUARDIAN_OLLAMA_MODEL.')
    details = local_request('/api/show', {'model': model})
    if details.get('remote_host') or details.get('remote_model') or re.search(r'^FROM\s+.*(?:https?://|cloud)', details.get('modelfile', ''), re.M | re.I):
        raise ValueError('Remote-backed models are not permitted for this local fallback')
    schema = {'type':'object', 'properties':{'edits':{'type':'array', 'minItems':1, 'maxItems':6,
        'items':{'type':'object', 'properties':{'file':{'type':'string'}, 'line':{'type':'integer'},
        'old':{'type':'string'}, 'new':{'type':'string'}}, 'required':['file','line','old','new'], 'additionalProperties':False}}},
        'required':['edits'], 'additionalProperties':False}
    result = local_request('/api/chat', {'model': model, 'stream': False, 'format': schema,
        'messages': [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}],
        'options': {'temperature': 0, 'num_predict': 1500, 'num_ctx': 8192}}, timeout=120)
    reply = ModelReply(result.get('message', {}).get('content', ''))
    reply.model = model
    reply.model_digest = next(m.get('digest') for m in models if m['name'] == model)
    return reply


def draft(scan, finding, node, read_source, store=None, model_chat=None):
    """Draft only from unchanged inventoried source; never write or execute repository code."""
    record = {'provider': 'guardian-harness / local Ollama', 'status': 'investigation',
              'verification': 'AI inference; neither a proven fix nor validated mitigation', 'steps': []}
    advisory = finding.get('what', '')
    if store is not None:
        from . import osv
        advisories, lookup = osv.query(node, store)
        ids = {finding.get('advisory'), *finding.get('aliases', [])} - {None}
        matched = [a for a in advisories if ids & {a.get('id'), *a.get('aliases', [])}]
        if matched:
            advisory = '\n'.join(a.get('summary', '') + '\n' + a.get('details', '') for a in matched)[:16000]
        record['advisory_lookup'] = lookup
    tokens = feature_tokens(advisory, node.get('name', ''))
    texts, allowed, hits = {}, {}, []
    for name in sorted(scan.get('files', {}))[:3000]:
        if Path(name).suffix not in ('.js', '.ts', '.tsx', '.jsx', '.mjs', '.cjs', '.py'): continue
        if any(p in ('node_modules', 'vendor', '.git', '.venv', 'dist') for p in Path(name).parts): continue
        text = read_source(scan, name)
        if text is None or len(text) > 200000: continue
        for line, value in enumerate(text.splitlines(), 1):
            if tokens and any(token in value for token in tokens) and len(value) <= 1000:
                texts[name] = text
                allowed[(name, line)] = value
                hits.append({'file': name, 'line': line, 'text': value})
                if len(hits) >= 12: break
        if len(hits) >= 12: break
    record['steps'].append({'agent': 'Investigator', 'feature_tokens': tokens, 'sites': hits})
    if not hits:
        record['reason'] = 'No advisory-named vulnerable feature located in unchanged source. Manual investigation is required; absence of a match does not prove the dependency is unused.'
        return record, []
    prompt = '<DATA>\n' + json.dumps({'package': node.get('name'), 'advisory': advisory, 'lines': hits}) + '\n</DATA>'
    record['prompt_hash'] = hashlib.sha256((PATCH_SYSTEM + prompt).encode()).hexdigest()
    def traced_chat(system, user):
        reply = (model_chat or chat)(system, user)
        record['model'] = getattr(reply, 'model', 'injected test/provider callable')
        record['model_digest'] = getattr(reply, 'model_digest', None)
        record['temperature'] = 0
        return reply
    for attempt in range(2):
        data, error = _chat_json(PATCH_SYSTEM, prompt, traced_chat)
        try:
            edits = (data or {}).get('edits')
            if not isinstance(edits, list) or not 0 < len(edits) <= 6: raise ValueError(error or 'No usable edits returned')
            seen, changed = set(), {}
            for edit in edits:
                if not isinstance(edit, dict): raise ValueError('Malformed edit')
                name, line = edit.get('file'), edit.get('line')
                if not isinstance(name, str) or type(line) is not int: raise ValueError('Invalid file or line')
                key = (name, line)
                if key not in allowed or key in seen or edit.get('old') != allowed[key]: raise ValueError('Edit is outside allowed sites, duplicated, or stale')
                new = edit.get('new')
                if not isinstance(new, str) or not new.strip() or len(new) > 4000 or '\0' in new or new == edit['old']:
                    raise ValueError('Empty, unchanged or invalid replacement')
                seen.add(key)
                lines = changed.setdefault(name, texts[name].splitlines(True))
                ending = '\r\n' if lines[line-1].endswith('\r\n') else '\n' if lines[line-1].endswith('\n') else ''
                lines[line-1] = new.rstrip('\r\n') + ending
            result = [{'file': name, 'before_hash': scan['files'][name]['hash'], 'after': ''.join(lines)} for name, lines in changed.items()]
            record.update(status='drafted', reason='Review the proposed mitigation, then approve Docker build/test and rescan. The dependency may remain vulnerable.')
            record['steps'].append({'agent': 'Patch author', 'attempts': attempt+1, 'status': 'drafted'})
            record['diff'] = ''.join(''.join(difflib.unified_diff(texts[e['file']].splitlines(True), e['after'].splitlines(True), fromfile='a/'+e['file'], tofile='b/'+e['file'])) for e in result)
            return record, result
        except (ValueError, TypeError, KeyError) as exc:
            record['reason'] = str(exc)
    record['status'] = 'unavailable'
    return record, []
