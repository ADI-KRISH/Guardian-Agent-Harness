"""SBOM I/O: write CycloneDX 1.5 JSON; read CycloneDX JSON and SPDX 2.x JSON.

Reading lets the Guardian consume SBOMs from other tools (syft for container
images, cyclonedx-npm / cyclonedx-maven-plugin, GitHub dependency graph export).
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import unquote

from .. import __version__
from ..models import Component, Inventory, ROOT_ID

ECO_FROM_PURL = {"npm": "npm", "maven": "maven", "pypi": "pypi", "docker": "docker", "oci": "docker",
                 "githubactions": "github-actions", "deb": "deb", "apk": "apk", "rpm": "rpm",
                 "golang": "go", "cargo": "cargo", "gem": "rubygems", "nuget": "nuget"}
SRI_ALG = {"sha512": "SHA-512", "sha384": "SHA-384", "sha256": "SHA-256", "sha1": "SHA-1"}


def sri_to_hashes(sri: Optional[str]):
    out = []
    for part in (sri or "").split():
        alg, _, b64 = part.partition("-")
        if alg in SRI_ALG:
            try:
                raw = base64.b64decode(b64)
            except (binascii.Error, ValueError):
                continue
            if len(raw) == {"sha512": 64, "sha384": 48, "sha256": 32, "sha1": 20}[alg]:
                out.append({"alg": SRI_ALG[alg], "content": raw.hex()})
    return out


SPDX_IDS = re.compile(r"^(MIT|MIT-0|ISC|0BSD|Apache-2\.0|BSD-[234]-Clause|BSD-3-Clause-Clear|GPL-[23]\.0(-only|-or-later)?|"
                      r"LGPL-2\.1(-only|-or-later)?|LGPL-3\.0(-only|-or-later)?|AGPL-3\.0(-only|-or-later)?|MPL-2\.0|"
                      r"Unlicense|CC0-1\.0|CC-BY-[34]\.0|BlueOak-1\.0\.0|Python-2\.0|WTFPL|Zlib|Artistic-2\.0|"
                      r"EPL-[12]\.0|AFL-2\.1|BSL-1\.0|EUPL-1\.2|PSF-2\.0|Unicode-DFS-2016|OFL-1\.1)$")


def _license(lic) -> list:
    lic = str(lic)
    if SPDX_IDS.match(lic):
        return [{"license": {"id": lic}}]
    if re.search(r"\s(OR|AND|WITH)\s", lic) or lic.startswith("("):
        return [{"expression": lic}]
    return [{"license": {"name": lic}}]


def write_cyclonedx(inv: Inventory, path: Path) -> dict:
    comps = []
    for c in sorted(inv.components.values(), key=lambda x: x.id):
        entry = {
            "type": {"container": "container", "application": "application"}.get(c.type, "library"),
            "bom-ref": c.id, "name": c.name, "purl": c.purl,
        }
        if c.version:
            entry["version"] = c.version
        if c.ecosystem == "maven" and ":" in c.name:
            entry["group"], entry["name"] = c.name.split(":", 1)
        elif c.name.startswith("@") and "/" in c.name:
            entry["group"], entry["name"] = c.name.split("/", 1)
        entry["scope"] = "optional" if c.scope in ("dev", "optional", "build", "ci") else "required"
        h = sri_to_hashes(c.integrity)
        if h:
            entry["hashes"] = h
        if c.license:
            entry["licenses"] = _license(c.license)
        if c.resolved:
            entry["externalReferences"] = [{"type": "distribution", "url": c.resolved}]
        props = [{"name": "guardian:scope", "value": c.scope}, {"name": "guardian:direct", "value": str(c.direct).lower()},
                 {"name": "guardian:ecosystem", "value": c.ecosystem}]
        if c.has_install_script:
            props.append({"name": "guardian:hasInstallScript", "value": "true"})
        if c.integrity:
            props.append({"name": "guardian:integrity", "value": c.integrity})
        for loc in c.locations[:5]:
            props.append({"name": "guardian:location", "value": loc})
        for k, v in c.properties.items():
            props.append({"name": f"guardian:{k}", "value": str(v)})
        entry["properties"] = props
        comps.append(entry)
    deps = [{"ref": ROOT_ID, "dependsOn": sorted(inv.edges.get(ROOT_ID, ()))}]
    for c in sorted(inv.components):
        deps.append({"ref": c, "dependsOn": sorted(inv.edges.get(c, ()))})
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "supply-chain-guardian", "version": __version__}]},
            "component": {"type": "application", "bom-ref": ROOT_ID, "name": inv.project},
            "properties": [{"name": "guardian:source", "value": s} for s in inv.sources],
        },
        "components": comps,
        "dependencies": deps,
    }
    path.write_text(json.dumps(bom, indent=2))
    return bom


def _eco_from_purl(purl: str) -> str:
    if not purl or not purl.startswith("pkg:"):
        return "generic"
    return ECO_FROM_PURL.get(purl[4:].split("/", 1)[0].lower(), purl[4:].split("/", 1)[0].lower())


def _prop(entry: dict, name: str):
    for p in entry.get("properties") or []:
        if p.get("name") == name:
            return p.get("value")
    return None


def read_sbom(path: Path, inv: Inventory) -> str:
    data = json.loads(Path(path).read_text())
    inv.sources.append(str(path))
    if data.get("bomFormat") == "CycloneDX":
        _read_cdx(data, inv, str(path))
        return "cyclonedx"
    if data.get("spdxVersion"):
        _read_spdx(data, inv, str(path))
        return "spdx"
    raise ValueError(f"{path}: not a CycloneDX or SPDX JSON document")


def _read_cdx(data: dict, inv: Inventory, src: str) -> None:
    meta_ref = ((data.get("metadata") or {}).get("component") or {}).get("bom-ref")
    if inv.project in ("", "unknown") and (data.get("metadata") or {}).get("component"):
        inv.project = data["metadata"]["component"].get("name", inv.project)
    ref_map = {}

    def visit(entries):
        for e in entries or []:
            purl = e.get("purl") or ""
            eco = _prop(e, "guardian:ecosystem") or _eco_from_purl(purl)
            name = e.get("name", "")
            grp = e.get("group")
            if grp:
                name = f"{grp}:{name}" if eco == "maven" else f"{grp}/{name}"
            integrity = _prop(e, "guardian:integrity")
            locs = [p["value"] for p in e.get("properties") or [] if p.get("name") == "guardian:location"]
            extra = {p["name"][9:]: p["value"] for p in e.get("properties") or []
                     if p.get("name", "").startswith("guardian:") and p["name"][9:] not in
                     ("scope", "direct", "ecosystem", "hasInstallScript", "integrity", "location")}
            resolved = next((r.get("url") for r in e.get("externalReferences") or [] if r.get("type") == "distribution"), None)
            c = Component(
                name=name, version=e.get("version"), ecosystem=eco,
                type={"container": "container", "application": "application"}.get(e.get("type"), "library"),
                scope=_prop(e, "guardian:scope") or ("optional" if e.get("scope") == "optional" else "prod"),
                direct=(_prop(e, "guardian:direct") == "true"), purl=unquote(purl) if purl and eco != "npm" else purl,
                source_files=[Path(src).name], locations=locs, resolved=resolved, integrity=integrity,
                has_install_script=_prop(e, "guardian:hasInstallScript") == "true", properties=extra,
            )
            if not c.purl:
                c.purl = c.__class__(name=name, version=c.version, ecosystem=eco).purl
            added = inv.add(c)
            ref_map[e.get("bom-ref") or added.id] = added.id
            visit(e.get("components"))

    visit(data.get("components"))
    roots = {meta_ref, ROOT_ID} - {None}
    depended = set()
    for d in data.get("dependencies") or []:
        parent = ROOT_ID if d.get("ref") in roots else ref_map.get(d.get("ref"))
        if parent is None:
            continue
        for child in d.get("dependsOn") or []:
            if child in ref_map:
                inv.link(parent, ref_map[child])
                depended.add(ref_map[child])
    if not inv.edges.get(ROOT_ID):
        # no root info: anything nobody depends on hangs off the root
        for cid in ref_map.values():
            if cid not in depended:
                inv.link(ROOT_ID, cid)
                inv.components[cid].direct = True


def _read_spdx(data: dict, inv: Inventory, src: str) -> None:
    ids = {}
    described = set(data.get("documentDescribes") or [])
    for p in data.get("packages") or []:
        purl = next((r.get("referenceLocator") for r in p.get("externalRefs") or []
                     if r.get("referenceType") == "purl"), "")
        if p.get("SPDXID") in described and not purl:
            ids[p["SPDXID"]] = ROOT_ID
            inv.project = p.get("name", inv.project)
            continue
        eco = _eco_from_purl(purl)
        checks = p.get("checksums") or []
        integrity = None
        for ch in checks:
            alg = ch.get("algorithm", "").lower().replace("-", "")
            if alg in ("sha512", "sha256", "sha1"):
                try:
                    integrity = f"{alg}-{base64.b64encode(bytes.fromhex(ch['checksumValue'])).decode()}"
                except ValueError:
                    pass
                break
        c = Component(name=p.get("name", ""), version=p.get("versionInfo"), ecosystem=eco, purl=purl,
                      source_files=[Path(src).name], integrity=integrity,
                      license=p.get("licenseConcluded") if p.get("licenseConcluded") not in (None, "NOASSERTION") else None,
                      resolved=p.get("downloadLocation") if p.get("downloadLocation") not in (None, "NOASSERTION", "NONE") else None)
        ids[p["SPDXID"]] = inv.add(c).id
    depended = set()
    for r in data.get("relationships") or []:
        a, t, b = r.get("spdxElementId"), r.get("relationshipType"), r.get("relatedSpdxElement")
        if t in ("DEPENDS_ON", "CONTAINS", "DEPENDENCY_OF") and a in ids and b in ids:
            parent, child = (ids[a], ids[b]) if t != "DEPENDENCY_OF" else (ids[b], ids[a])
            inv.link(parent, child)
            depended.add(child)
        elif t == "DESCRIBES" and b in ids and ids[b] != ROOT_ID:
            inv.link(ROOT_ID, ids[b])
    for cid in set(ids.values()) - depended - {ROOT_ID}:
        if not any(cid in v for v in inv.edges.values()):
            inv.link(ROOT_ID, cid)
            inv.components[cid].direct = True
