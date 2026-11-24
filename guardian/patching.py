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
