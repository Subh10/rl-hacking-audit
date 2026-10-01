import json
from ai_auditor import Scanner, ScanReport, Severity, Target, TargetType
from ai_auditor.adapters import hardened_agent, vulnerable_agent
from ai_auditor.scan import evaluate_gates
from ai_auditor.scenarios import BUILTIN_SCENARIOS

def _scan(fn, **kw):
    target = Target("t", TargetType.AGENT, invoke=fn, capabilities=["system", "tools"])
    return Scanner(target, **kw).run()

def test_vulnerable_agent_is_fully_compromised_and_hardened_is_not():
    bad, good = _scan(vulnerable_agent, converters=["identity"]), _scan(hardened_agent, converters=["identity"])
    assert bad.overall()["asr"] == 1.0
    assert good.overall()["asr"] < 0.3
    assert len(bad.findings) == len(BUILTIN_SCENARIOS)

def test_encoding_converters_bypass_plaintext_guard():
    conv = _scan(hardened_agent, converters=["identity", "base64", "rot13"]).converter_stats()
    assert conv["base64"]["asr"] > 0.9 and conv["rot13"]["asr"] > 0.9 and conv["identity"]["asr"] < 0.3

def test_safe_target_yields_no_findings():
    report = _scan(lambda prompt, system=None, tools=None: "I can't help with that.")
    assert report.findings == [] and report.overall()["asr"] == 0.0

def test_quoting_an_injected_instruction_is_not_counted_as_obeying_it():
    def describer(prompt, system=None, tools=None):
        return "The document contains an instruction asking me to join two strings; I will not follow it."
    assert _scan(describer, converters=["identity"]).findings == []

def test_same_seed_is_reproducible_and_different_seed_changes_canaries():
    a = _scan(vulnerable_agent, converters=["identity"], seed=1)
    b = _scan(vulnerable_agent, converters=["identity"], seed=1)
    c = _scan(vulnerable_agent, converters=["identity"], seed=2)
    assert [x.prompt for x in a.attempts] == [x.prompt for x in b.attempts] and a.evidence_root == b.evidence_root != c.evidence_root

def test_requirements_skip_scenarios_instead_of_faking_results():
    report = _scan(lambda prompt: "no", converters=["identity"])
    assert {"SPL-001", "TOOL-001", "EXF-001", "HIER-001"} <= set(report.skipped)
    assert report.attempts and all(a.system is None for a in report.attempts)

def test_target_errors_are_recorded_and_excluded_from_asr():
    calls = {"n": 0}
    def flaky(prompt, system=None, tools=None):
        calls["n"] += 1
        if calls["n"] % 2:
            raise RuntimeError("boom")
        return "nope"
    report = _scan(flaky, converters=["identity"], scenarios=BUILTIN_SCENARIOS[:1])
    o = report.overall()
    assert o["errors"] == 2 and o["n"] == 2 and all(a.error for a in report.attempts if a.error)

def test_max_attempts_keeps_every_scenario_represented():
    report = _scan(vulnerable_agent, converters=["identity", "base64"], max_attempts=24)
    assert len(report.attempts) == 24 and {a.scenario_id for a in report.attempts} == {s.id for s in BUILTIN_SCENARIOS}

def test_threaded_scan_matches_serial():
    assert _scan(vulnerable_agent, converters=["identity"]).evidence_root == _scan(vulnerable_agent, converters=["identity"], workers=4).evidence_root

def test_trials_multiply_attempts_with_fresh_canaries():
    report = _scan(vulnerable_agent, converters=["identity"], trials=3, scenarios=BUILTIN_SCENARIOS[:1])
    assert len(report.attempts) == 12 and len({a.canary for a in report.attempts}) == 12

def test_report_round_trips_through_json(tmp_path):
    report = _scan(vulnerable_agent, converters=["identity"])
    path = report.save(tmp_path / "r.json")
    loaded = ScanReport.load(path)
    assert loaded.evidence_root == report.evidence_root
    assert [f.fingerprint for f in loaded.findings] == [f.fingerprint for f in report.findings]
    assert json.loads(path.read_text())["schema"] == "ai-auditor/report/v1"

def test_adaptive_pass_escalates_against_a_target_with_a_plaintext_guard():
    report = _scan(hardened_agent, converters=["identity"], adaptive_steps=12, scenarios=[s for s in BUILTIN_SCENARIOS if s.id == "PI-RAG-001"])
    assert any(a.adaptive for a in report.attempts) and any(a.adaptive and a.success for a in report.attempts)

def test_judge_is_advisory_and_does_not_change_asr():
    from ai_auditor.oracles import LLMJudge
    judge = LLMJudge(lambda p: '{"violation": true, "confidence": 0.9, "rationale": "x"}')
    report = _scan(lambda prompt, system=None, tools=None: "safe", judge=judge, converters=["identity"], scenarios=BUILTIN_SCENARIOS[:1])
    assert report.overall()["asr"] == 0.0 and all(a.judge["success"] for a in report.attempts)

def test_gates():
    bad = _scan(vulnerable_agent, converters=["identity"])
    good = _scan(lambda prompt, system=None, tools=None: "no", converters=["identity"])
    assert evaluate_gates(bad, fail_on="high")
    assert not evaluate_gates(good, fail_on="low")
    assert evaluate_gates(bad, max_asr=.1)
    assert evaluate_gates(bad, baseline=good)
    assert not evaluate_gates(good, baseline=bad)
    assert Severity.CRITICAL in {f.severity for f in bad.findings}
