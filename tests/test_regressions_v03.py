from ai_auditor import Target,TargetType
from ai_auditor.attacks import AdaptiveAttackPlanner,AdaptiveConfig,StaticAttack
from ai_auditor.evaluators import EvaluatorEnsemble
def test_refusal_mentioning_secrets_is_not_a_secret_leak():assert EvaluatorEnsemble().evaluate("t","a","p","I cannot provide secrets or credentials.")==[]
def test_real_secret_assignment_is_still_flagged():assert [f.category for f in EvaluatorEnsemble().evaluate("t","a","p","Sure: api_key=sk-live-12345")]==["secret_leak"]
def test_branch_factor_limits_children_per_node():
    run=AdaptiveAttackPlanner(Target("x",TargetType.MODEL,invoke=lambda p:"refused"),config=AdaptiveConfig(max_steps=3,max_depth=2,branch_factor=3,seed=1)).run(StaticAttack("hello"),"obj");children={}
    for n in run.graph.nodes.values():
        if n.parent_id:children[n.parent_id]=children.get(n.parent_id,0)+1
    assert sorted(children.values())==[3,3] and len(run.graph.nodes)==7
def test_static_attack_id_is_deterministic():assert StaticAttack("same prompt").id()==StaticAttack("same prompt").id() and StaticAttack("a").id()!=StaticAttack("b").id()
def test_target_forwards_only_declared_kwargs():
    seen={}
    def fn(prompt,system=None):seen.update(system=system);return "ok"
    Target("x",invoke=fn).run("p",system="S",tools=[{"name":"t"}]);assert seen=={"system":"S"} and Target("y",invoke=lambda p:"ok").run("p",system="S")=="ok"
