"""Orchestrator: plans a run from memory, runs the agents, and logs every decision with its reason."""
from __future__ import annotations

import re
import time
from pathlib import Path

from . import canary, config, llm
from .agents import discovery
from .memory import Memory
from .pipeline import Pipeline
from .tools import git


def _safe(ref: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", ref)


class Run:
    def __init__(self, src: str, base: str | None, head: str | None, use_llm: bool = True, log=print):
        self.src, self.base_arg, self.head_arg, self.use_llm, self.log = src, base, head, use_llm, log
        self.project = git.project_name(src)
        self.id = time.strftime("%Y%m%d-%H%M%S")
        self.mem = Memory()
        self.out: dict = {"run_id": self.id, "project": self.project, "source": src}

    def decide(self, actor, decision, why, inputs=None, rule="", confidence=""):
        self.mem.decide(self.id, self.project, actor, decision, why, inputs, rule, confidence)
        self.log(f"  [{actor}] {decision}: {why}")

    def execute(self) -> dict:
        ws = config.WORKSPACE
        t0 = time.time()
        self.log(f"Guardian run {self.id} on {self.src}")
        repo = git.clone(self.src, ws / "repos" / self.project)
        cfg = config.load(None)

        # ---- plan: which refs to compare ----
        local = Path(self.src).exists()
        head_ref = self.head_arg or ("HEAD" if local else "origin/HEAD")
        approved = self.mem.get_baseline(self.project, self.base_arg) if True else None
        if self.base_arg:
            base_ref, base_why = self.base_arg, "chosen by the operator"
        elif approved:
            base_ref, base_why = approved[0], "latest human-approved baseline in memory"
        else:
            tags = git.latest_tags(repo)
            base_ref = tags[0] if tags else None
            base_why = (f"no approved baseline yet, so using the latest release tag {base_ref} (not yet approved by a human)"
                        if base_ref else "no baseline and no tags: scanning without a comparison")
        if base_ref and git.resolve(repo, base_ref) == git.resolve(repo, head_ref):
            tags = git.latest_tags(repo)
            base_ref = tags[1] if len(tags) > 1 else None
            base_why += "; head equals that tag, so using the previous tag instead"
        self.decide("orchestrator", f"compare {base_ref} -> {head_ref}", base_why, rule="plan")
        self.out.update(base_ref=base_ref, head_ref=head_ref,
                        head_commit=git.commit_info(repo, head_ref), base_commit=git.commit_info(repo, base_ref) if base_ref else None)
        self.mem.start_run(self.id, self.project, base_ref or "", head_ref)

        head_dir = git.checkout(repo, head_ref, ws / "checkouts" / self.project / _safe(head_ref))
        cfg = config.load(head_dir)
        if (head_dir / "guardian.yaml").exists():
            self.decide("orchestrator", "load guardian.yaml", "project config found in the repo; it only narrows or extends defaults")
        lessons = self.mem.active_lessons(self.project)
        self.decide("orchestrator", f"load {len(lessons)} active lesson(s)", "lessons are human-approved and scoped", rule="lesson")

        # ---- canary ----
        self.log("Canary self-check...")
        canary_results, canary_findings = canary.run()
        missed = [r["detector"] for r in canary_results if not r["caught"]]
        self.decide("orchestrator", "canary check", "all detectors caught their planted sample" if not missed else f"MISSED: {missed}",
                    {"results": canary_results}, rule="canary")
        self.out["canary"] = canary_results

        # ---- discover ----
        self.log("Discovery agent: head...")
        head = discovery.snapshot(head_dir)
        self.decide("discovery-agent", f"snapshot head: {len(head['packages'])} packages, {len(head['workflows'])} workflow steps, {len(head['images'])} base images",
                    "SBOM from Syft plus lockfile parsing", head.get("sbom_tool"))
        base = None
        if base_ref:
            if approved and approved[0] == base_ref:
                base = approved[1]
                self.decide("discovery-agent", f"use stored baseline snapshot {base_ref}", "approved by a human earlier; not recomputed")
            else:
                self.log(f"Discovery agent: baseline {base_ref}...")
                base_dir = git.checkout(repo, base_ref, ws / "checkouts" / self.project / _safe(base_ref))
                base = discovery.snapshot(base_dir, run_syft=True)
                self.decide("discovery-agent", f"snapshot baseline {base_ref}: {len(base['packages'])} packages", "lockfile parsing of the baseline checkout")
        self.out["notes"] = head["notes"]
        if head.get("generated_locks"):
            self.decide("discovery-agent", f"resolve lockfiles for {head['generated_locks']}",
                        "the repo commits no lockfile; resolved with npm --package-lock-only --ignore-scripts, which runs no package code",
                        rule="no-code-execution")

        # ---- investigate in parallel ----
        pl = Pipeline(self, cfg, repo, head_dir, base_ref, head_ref, head, base, lessons, canary_findings)
        if self.use_llm and llm.agentic_ok(cfg):
            self.log(f"Lead agent ({cfg['llm']['model']}) is planning the investigation...")
            pl.run_agentic()
        else:
            self.log("Running the specialist agents in the fixed order...")
            pl.run_fixed()
        findings, change_summary, bstats = pl.findings, pl.change_summary, pl.bstats
        if pl.summary:
            self.out["agent_summary"] = pl.summary

        # ---- one-shot AI explanations for the top findings the lead did not investigate (labelled inference) ----
        if self.use_llm and cfg["llm"]["provider"] != "none":
            todo = [f for f in findings if not f.get("suppressed_by") and not f["ai_inference"]][: cfg["llm"]["max_findings_explained"]]
            self.log(f"Asking {cfg['llm']['provider']}:{cfg['llm']['model']} to explain {len(todo)} findings...")
            for f in todo:
                ans = llm.ask(cfg, llm.facts_for(f))
                if ans and ans.get("text"):
                    f["ai_inference"].append(ans)
                elif ans and ans.get("error"):
                    self.decide("evidence-agent", "skip AI explanations", f"LLM unavailable: {ans['error']}")
                    break
        for f in findings:
            self.decide("evidence-agent", f"rate {f['id']} {f['risk_level']} ({f['score']})", f["score_explanation"],
                        {"title": f["title"]}, rule="score", confidence=f.get("confidence", ""))

        self.mem.save_findings(self.id, self.project, findings)
        active = [f for f in findings if not f.get("suppressed_by")]
        summary = {
            "packages": len(head["packages"]),
            "direct": len({k for v in head["roots"].values() for k in v}),
            "runtime": sum(1 for p in head["packages"].values() if p["scope"] == "runtime"),
            "dev": sum(1 for p in head["packages"].values() if p["scope"] == "dev"),
            "ecosystems": sorted({p["ecosystem"] for p in head["packages"].values()}),
            "lockfiles": sorted({l for p in head["packages"].values() for l in p["lockfiles"]}),
            "workflow_steps": len(head["workflows"]),
            "images": len(head["images"]),
            "findings": len(active),
            "suppressed": len(findings) - len(active),
            "by_level": {lvl: sum(1 for f in active if f["risk_level"] == lvl) for lvl in ("Critical", "High", "Medium", "Low")},
            "seconds": round(time.time() - t0, 1),
        }
        self.mem.finish_run(self.id, summary)
        self.out.update(summary=summary, change=change_summary, findings=findings, head=head,
                        backdoor_stats=bstats if base_ref else {}, decisions=self.mem.decisions(self.id))
        return self.out
