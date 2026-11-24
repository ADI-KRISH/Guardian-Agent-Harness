"""Run: python -m unittest discover -s tests -v   (no network needed)"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ["GUARDIAN_OFFLINE"] = "1"
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from guardian import net  # noqa: E402
net.OFFLINE = True
from guardian.versions import satisfies, in_osv_range, cmp  # noqa: E402
from guardian.detect import cvss, vulns, packages, infra, changes, load_baseline  # noqa: E402
from guardian.detect import detect  # noqa: E402
from guardian.discover import discover, write_outputs  # noqa: E402
from guardian.discover.sbom import read_sbom, write_cyclonedx  # noqa: E402
from guardian.models import Inventory, ROOT_ID  # noqa: E402


class Versions(unittest.TestCase):
    def test_ranges(self):
        self.assertTrue(satisfies("4.17.15", "<4.17.21"))
        self.assertFalse(satisfies("4.17.21", "<4.17.21"))
        self.assertTrue(satisfies("3.8.0", ">=3.7.0 <4.17.19"))
        self.assertTrue(satisfies("0.1.1", "=0.1.1"))
        self.assertTrue(satisfies("1.2.5", ">=1.0.0 <1.2.6 || >=2.0.0"))
        self.assertTrue(satisfies("1.2.9", "^1.2.0"))
        self.assertFalse(satisfies("2.0.0", "^1.2.0"))
        self.assertTrue(cmp("1.0.0-beta", "1.0.0") < 0)

    def test_osv_events(self):
        ev = [{"introduced": "0"}, {"fixed": "4.17.21"}]
        self.assertTrue(in_osv_range("4.17.20", ev))
        self.assertFalse(in_osv_range("4.17.21", ev))
        self.assertTrue(in_osv_range("2.5.1", [{"introduced": "2.0"}, {"last_affected": "2.5.1"}]))

    def test_cvss(self):
        self.assertEqual(cvss.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss.score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"), 7.2)


class NpmDiscovery(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"a": "^1.0.0", "b": "1.0.0"}}))
        lock = {"lockfileVersion": 3, "packages": {
            "": {"name": "app", "dependencies": {"a": "^1.0.0", "b": "1.0.0"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"c": "^2"}},
            "node_modules/b": {"version": "1.0.0", "dependencies": {"c": "^1"}},
            "node_modules/b/node_modules/c": {"version": "1.5.0"},
            "node_modules/c": {"version": "2.0.0"},
        }}
        (self.d / "package-lock.json").write_text(json.dumps(lock))

    def test_nested_resolution(self):
        inv, _ = discover(self.d)
        self.assertIn("pkg:npm/c@2.0.0", inv.edges["pkg:npm/a@1.0.0"])
        self.assertIn("pkg:npm/c@1.5.0", inv.edges["pkg:npm/b@1.0.0"])
        self.assertEqual(inv.paths_to("pkg:npm/c@1.5.0")[0], [ROOT_ID, "pkg:npm/b@1.0.0", "pkg:npm/c@1.5.0"])
        self.assertFalse(inv.components["pkg:npm/c@2.0.0"].direct)

    def test_sbom_roundtrip(self):
        inv, _ = discover(self.d)
        out = Path(tempfile.mkdtemp()) / "s.json"
        write_cyclonedx(inv, out)
        inv2 = Inventory(project="x")
        read_sbom(out, inv2)
        self.assertEqual(set(inv.components), set(inv2.components))
        self.assertEqual(inv.edges.get("pkg:npm/b@1.0.0"), inv2.edges.get("pkg:npm/b@1.0.0"))


class OtherEcosystems(unittest.TestCase):
    def test_maven_pom_and_tgf(self):
        d = Path(tempfile.mkdtemp())
        (d / "pom.xml").write_text("""<project xmlns="http://maven.apache.org/POM/4.0.0"><groupId>g</groupId>
<artifactId>app</artifactId><version>1.0</version><properties><log4j.version>2.14.1</log4j.version></properties>
<dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>
<version>${log4j.version}</version></dependency></dependencies></project>""")
        tgf = d / "tree.tgf"
        tgf.write_text("1 g:app:jar:1.0\n2 org.apache.logging.log4j:log4j-core:jar:2.14.1:compile\n"
                       "3 org.apache.logging.log4j:log4j-api:jar:2.14.1:compile\n#\n1 2 compile\n2 3 compile\n")
        inv, _ = discover(d, maven_tree=tgf)
        core = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
        self.assertTrue(inv.components[core].direct)
        self.assertIn("pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1", inv.edges[core])

    def test_spdx_import(self):
        d = Path(tempfile.mkdtemp())
        spdx = {"spdxVersion": "SPDX-2.3", "documentDescribes": ["SPDXRef-root"], "packages": [
            {"SPDXID": "SPDXRef-root", "name": "img"},
            {"SPDXID": "SPDXRef-p1", "name": "openssl", "versionInfo": "3.0.2",
             "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:deb/ubuntu/openssl@3.0.2"}]}],
            "relationships": [{"spdxElementId": "SPDXRef-root", "relationshipType": "DEPENDS_ON",
                               "relatedSpdxElement": "SPDXRef-p1"}]}
        (d / "x.spdx.json").write_text(json.dumps(spdx))
        inv = Inventory(project="t")
        read_sbom(d / "x.spdx.json", inv)
        self.assertIn("pkg:deb/ubuntu/openssl@3.0.2", inv.edges[ROOT_ID])


class Detection(unittest.TestCase):
    def test_osv_parsing_mocked(self):
        d = Path(tempfile.mkdtemp())
        (d / "package.json").write_text(json.dumps({"name": "a", "dependencies": {"lodash": "4.17.15"}}))
        (d / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"lodash": "4.17.15"}}, "node_modules/lodash": {"version": "4.17.15"}}}))
        inv, _ = discover(d)
        vuln = {"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"], "summary": "Command Injection in lodash",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
                "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                              "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}

        def fake(url, body=None, **kw):
            if "querybatch" in url:
                return {"results": [{"vulns": [{"id": vuln["id"]}]} for _ in body["queries"]]}
            return vuln
        with mock.patch.object(net, "fetch_json", side_effect=fake):
            fs, meta = vulns.detect(inv, "osv")
        self.assertEqual(meta["source"], "osv.dev")
        self.assertEqual(fs[0].severity, "high")
        self.assertEqual(fs[0].fix["fixed_versions"], ["4.17.21"])
        self.assertIn("CVE-2021-23337", fs[0].identifiers)

    def test_demo_all_attacks_offline(self):
        subprocess.run([sys.executable, str(ROOT / "tools" / "make_demo.py")], check=True, capture_output=True)
        inv, ctx = discover(ROOT / "demo" / "compromised")
        res = detect(inv, ctx, vuln_source="offline", baseline=ROOT / "demo" / "baseline" / "package-lock.json",
                     online=False)
        rules = {(f.rule, (f.component or {}).get("name")) for f in res["findings"]}
        expect = [("CHANGE-INTEGRITY", "lodash"), ("TYPOSQUAT", "crossenv"), ("INSTALL-SCRIPT", "crossenv"),
                  ("INTEGRITY-INSECURE-URL", "minimist"), ("CHANGE-SOURCE", "minimist"),
                  ("UNEXPECTED-LOCK-ONLY-DEP", "debug-helper-utils"), ("INTEGRITY-MISSING", "debug-helper-utils"),
                  ("UNEXPECTED-ORPHAN", "ua-parser-js"), ("IMAGE-UNTRUSTED-SOURCE", "fastbuilds/node-runtime"),
                  ("IMAGE-MUTABLE-TAG", "node"), ("CICD-UNPINNED-ACTION", "quick-actions/npm-cache")]
        for e in expect:
            self.assertIn(e, rules, e)
        self.assertTrue(any(f.category == "malicious-package" and f.component["name"] == "flatmap-stream"
                            for f in res["findings"]))
        crossenv_script = [f for f in res["findings"] if f.rule == "INSTALL-SCRIPT" and f.component["name"] == "crossenv"][0]
        self.assertEqual(crossenv_script.severity, "critical")
        self.assertTrue(all(v["status"] == "ok" for v in res["meta"]["checks"].values()), res["meta"]["checks"])

    def test_graph_views(self):
        from guardian import graph
        inv, ctx = discover(ROOT / "demo" / "compromised")
        res = detect(inv, ctx, vuln_source="offline", online=False)
        dot = graph.risk_subgraph_dot(inv, res["findings"], "high")
        self.assertIn('"pkg:npm/event-stream@3.3.6" -> "pkg:npm/flatmap-stream@0.1.1"', dot)
        self.assertNotIn("pkg:npm/accepts@", dot)          # clean packages are left out
        t = graph.tree_data(inv, res["findings"])
        self.assertEqual(t["nodes"][0]["b"], "critical")   # root sees the worst risk below it
        labels = [t["nodes"][i]["l"] for i in t["orphans"]]
        self.assertIn("ua-parser-js@0.7.29", labels)

    def test_clean_baseline_has_no_tamper_findings(self):
        inv, ctx = discover(ROOT / "demo" / "baseline")
        res = detect(inv, ctx, vuln_source="offline", baseline=ROOT / "demo" / "baseline" / "package-lock.json",
                     online=False)
        bad = [f for f in res["findings"] if f.category in ("integrity", "typosquat", "unexpected-dependency", "malicious-package")]
        self.assertEqual(bad, [], [f.title for f in bad])


if __name__ == "__main__":
    unittest.main()
