import difflib
from pathlib import Path
from common import read_json, finding

POPULAR = """express lodash react react-dom axios moment chalk commander debug request async
bluebird underscore webpack typescript jquery vue angular body-parser cookie-parser jsonwebtoken
mongoose sequelize socket.io passport bcrypt uuid yargs glob minimist colors eslint mocha jest
dotenv cors helmet morgan nodemon rxjs""".split()

def scan(repo, base, new):
    root = Path(repo).name
    a = (read_json(repo, base, "package-lock.json") or {}).get("packages", {})
    b = (read_json(repo, new, "package-lock.json") or {}).get("packages", {})
    out = []
    for key, meta in b.items():
        if not key or key in a:
            continue
        name = key.split("node_modules/")[-1]
        if name in POPULAR:
            continue
        for p in POPULAR:
            if len(p) < 5 or abs(len(p) - len(name)) > 2:
                continue
            r = difflib.SequenceMatcher(None, name, p).ratio()
            if r >= 0.88:
                out.append(finding("typosquat", name, meta.get("version", "unknown"), "high",
                                   f"Possible typosquat: looks like '{p}'",
                                   f"{name} ~ {p} (similarity {r:.2f}); new in lockfile: {key}",
                                   root, "typosquat-detector"))
                break
    return out
