"""
Extract VERBATIM AgentDojo cases for the T6b corpus by running AgentDojo's OWN code (no LLM, no network).

  attacks : every v1 injection task (4 suites) rendered by AgentDojo's attack classes
            (`load_attack(name, suite, pipeline).attack(user_task, injection_task)`), i.e. the exact string
            AgentDojo places in its injection vectors. Each injection task is paired with an injectable user
            task (rotation over the suite's injectable user tasks, sorted by id) and the ground-truth tool call
            whose output carries the injection vector (found with AgentDojo's own canary method).
  benign  : every v1 user task run through AgentDojo's ground truth (GroundTruthPipeline logic) on the
            DEFAULT environment (injection vectors at their benign defaults, no attack). Tool outputs are
            rendered with AgentDojo's `tool_result_to_str` (yaml.safe_dump), exactly what the model sees.

Deterministic: sorted suites / task ids, no RNG, and two pinned sources of run-to-run variation:
  - PYTHONHASHSEED=0 (the script re-execs itself with it): AgentDojo de-duplicates some lists (e.g.
    calendar participants) through a Python set, whose order otherwise changes per process;
  - the wall clock: AgentDojo's write tools stamp `datetime.datetime.now()` (email_client sent-email
    timestamp, cloud_drive_client last_modified). We pin `now()` in those two modules to FROZEN_NOW
    (AgentDojo's own environment "current day", 2024-05-15). Nothing else in the tools is touched.
Output is JSON with sorted keys.

Usage (deps from any venv with agentdojo's requirements; CODE from the pinned clone):
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=<agentdojo clone>/src <python> extract-agentdojo.py <agentdojo clone> > out.json
The script refuses to run if `agentdojo` is not imported from <clone>/src (so a pip-installed copy can
never stand in for the pinned source). captures/variants/tools/verify-upstream.mjs re-runs it and compares
the output byte-for-byte with upstream-agentdojo.json.

AgentDojo: MIT, Copyright (c) 2024 Edoardo Debenedetti, Jie Zhang, Mislav Balunovic, Luca Beurer-Kellner,
Marc Fischer, and Florian Tramer. See ../LICENSES.md.
"""

import json
import os
import re
import sys

BENCHMARK_VERSION = "v1"
SUITES = ["banking", "slack", "travel", "workspace"]
# Primary attack (AgentDojo paper's strongest baseline, model/user-name independent) + one extra template
# per injection task, rotating over AgentDojo's fixed-template baselines.
PRIMARY_ATTACK = "important_instructions_no_names"
EXTRA_ATTACKS = ["ignore_previous", "injecagent", "system_message", "direct"]
# Only used to satisfy ImportantInstructionsAttack.__init__ (it resolves a model name, then the
# *_no_names subclass overrides it with DEFAULT_MODEL_NAME); fixed templates ignore it.
PIPELINE_NAME = "gpt-4o-2024-05-13"

FROZEN_NOW = (2024, 5, 15, 12, 0, 0)


def main():
    if os.environ.get("PYTHONHASHSEED") != "0":
        os.execve(sys.executable, [sys.executable, *sys.argv], {**os.environ, "PYTHONHASHSEED": "0"})
    if len(sys.argv) != 2:
        sys.exit("usage: extract-agentdojo.py <agentdojo clone root>")
    clone = os.path.realpath(sys.argv[1])
    import agentdojo

    got = os.path.realpath(os.path.dirname(agentdojo.__file__))
    want = os.path.join(clone, "src", "agentdojo")
    if got != want:
        sys.exit(f"refusing: agentdojo imported from {got}, expected the pinned clone {want} (set PYTHONPATH)")

    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite
    import datetime as _dt
    import types as _types
    from agentdojo.default_suites.v1.tools import cloud_drive_client, email_client

    class _FrozenDatetime(_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return _dt.datetime(*FROZEN_NOW, tzinfo=tz)

    frozen = _types.ModuleType("datetime")
    frozen.__dict__.update(_dt.__dict__)
    frozen.datetime = _FrozenDatetime
    for mod in (email_client, cloud_drive_client):
        if getattr(mod, "datetime", None) is not _dt:
            sys.exit(f"refusing: {mod.__name__}.datetime is not the datetime module; clock pin would not apply")
        mod.datetime = frozen

    class NamedPipeline(BasePipelineElement):
        name = PIPELINE_NAME

        def query(self, *a, **k):  # never called: no model is run
            raise RuntimeError("no LLM in extraction")

    pipeline = NamedPipeline()

    def task_key(tid):
        return int(re.sub(r"\D", "", tid))

    def run_ground_truth(suite, user_task, injections):
        """GroundTruthPipeline.query, inlined so we keep each call's rendered output."""
        runtime = FunctionsRuntime(suite.tools)
        env = suite.load_and_inject_default_environment(injections)
        env = user_task.init_environment(env)
        out = []
        for call in user_task.ground_truth(env):
            result, _ = runtime.run_function(env, call.function, call.args, raise_on_error=True)
            out.append({"tool": call.function, "args": dict(call.args), "output": tool_result_to_str(result)})
        return out

    templates = {}
    attacks = []
    benign = []
    for sname in SUITES:
        suite = get_suite(BENCHMARK_VERSION, sname)
        user_ids = sorted(suite.user_tasks, key=task_key)
        inj_ids = sorted(suite.injection_tasks, key=task_key)
        primary = load_attack(PRIMARY_ATTACK, suite, pipeline)

        # ---- benign: every user task, default (non-injected) environment ----------------------------
        for uid in user_ids:
            ut = suite.user_tasks[uid]
            calls = run_ground_truth(suite, ut, {})
            benign.append({"suite": sname, "userTask": uid, "prompt": ut.PROMPT, "calls": calls})

        # ---- attacks: injectable user tasks + the call whose output carries the vector ---------------
        injectable = []
        for uid in user_ids:
            ut = suite.user_tasks[uid]
            try:
                cands = primary.get_injection_candidates(ut)
            except ValueError:
                continue  # AgentDojo itself marks this user task "not injectable"
            canaries = primary.canary_injections
            calls = run_ground_truth(suite, ut, canaries)
            hit = next(
                (i for i, c in enumerate(calls) if any(canaries[v] in c["output"] for v in cands)),
                None,
            )
            if hit is None:
                raise SystemExit(f"{sname}/{uid}: injectable but no ground-truth call shows a canary")
            injectable.append((uid, calls[hit]["tool"], calls[hit]["args"]))
        if not injectable:
            raise SystemExit(f"{sname}: no injectable user task")

        for j, iid in enumerate(inj_ids):
            it = suite.injection_tasks[iid]
            uid, tool, args = injectable[j % len(injectable)]
            ut = suite.user_tasks[uid]
            for aname in (PRIMARY_ATTACK, EXTRA_ATTACKS[(len(attacks) // 2) % len(EXTRA_ATTACKS)]):
                atk = primary if aname == PRIMARY_ATTACK else load_attack(aname, suite, pipeline)
                templates[aname] = atk.jailbreak
                rendered = set(atk.attack(ut, it).values())
                if len(rendered) != 1:
                    raise SystemExit(f"{sname}/{uid}x{iid}/{aname}: expected one rendered string, got {len(rendered)}")
                attacks.append(
                    {
                        "suite": sname,
                        "injectionTask": iid,
                        "goal": it.GOAL,
                        "attack": aname,
                        "text": rendered.pop(),
                        "userTask": uid,
                        "prompt": ut.PROMPT,
                        "tool": tool,
                        "args": args,
                    }
                )

    json.dump(
        {
            "benchmarkVersion": BENCHMARK_VERSION,
            "suites": SUITES,
            "primaryAttack": PRIMARY_ATTACK,
            "extraAttacks": EXTRA_ATTACKS,
            "formatter": "agentdojo.agent_pipeline.tool_execution.tool_result_to_str (yaml.safe_dump)",
            "templates": templates,
            "attacks": attacks,
            "benign": benign,
        },
        sys.stdout,
        indent=1,
        sort_keys=True,
        ensure_ascii=False,
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
