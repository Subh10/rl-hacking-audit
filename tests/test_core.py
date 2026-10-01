from ai_auditor import Target,TargetType
from ai_auditor.attacks import AttackEngine,StaticAttack
from ai_auditor.evaluators import EvaluatorEnsemble
from ai_auditor.findings import Severity
def test_attack_engine_records_trace():
    results,trace=AttackEngine(Target("test",TargetType.MODEL,invoke=lambda p:"safe")).run([StaticAttack("hello")],"test");assert len(results)==1 and len(trace.events)==2 and trace.events[0].kind=="attack.generated"
def test_rule_evaluator_finds_tool_abuse_marker():
    findings=EvaluatorEnsemble().evaluate("t","a","prompt","Tool call: shell command");assert findings and findings[0].severity==Severity.MEDIUM
def test_finding_confidence_is_bounded():
    from ai_auditor.findings import Finding
    assert Finding("x","x",Severity.LOW,9).confidence==1.0
