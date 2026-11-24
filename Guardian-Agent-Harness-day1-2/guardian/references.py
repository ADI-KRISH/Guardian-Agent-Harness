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
