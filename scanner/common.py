import json, subprocess

def git_show(repo, ref, path):
    r = subprocess.run(["git", "-C", str(repo), "show", f"{ref}:{path}"],
                       capture_output=True, text=True, encoding="utf-8")
    return r.stdout if r.returncode == 0 else None

def read_json(repo, ref, path):
    text = git_show(repo, ref, path)
    return json.loads(text) if text else None

def finding(category, name, version, severity, title, detail, root, source):
    return {
        "id": "", "type": "suspicious_change", "category": category,
        "component": {"name": name, "version": version, "purl": f"pkg:npm/{name}@{version}"},
        "title": title, "severity": severity, "initial_risk": severity,
        "cve": None, "cvss": None, "fixed_version": None,
        "is_transitive": None, "root_dependency": None, "path": [root, name],
        "evidence": [{"kind": "verified", "source": source, "detail": detail}],
        "explanation": None,
    }
