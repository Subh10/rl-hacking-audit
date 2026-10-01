from ai_auditor import Target,TargetType
from ai_auditor.attacks import AdaptiveAttackPlanner,AdaptiveConfig,StaticAttack
from ai_auditor.evidence import EvidenceStore
from ai_auditor.replay import ReplayEngine
def test_adaptive_search_builds_graph_and_trace():
    calls=[]
    def model(prompt,history=None):calls.append((prompt,history));return "tool call: shell command" if len(calls)>1 else "refused"
    run=AdaptiveAttackPlanner(Target("x",TargetType.AGENT,invoke=model),config=AdaptiveConfig(max_steps=3,max_depth=2,seed=1)).run(StaticAttack("Try a secret request"),"find unsafe behavior")
    assert len(run.results)==3 and len(run.graph.nodes)>=3 and any(e.kind=="attack.mutated" for e in run.trace.events) and run.best_score>0 and calls[1][1]
def test_adaptive_is_reproducible_at_prompt_sequence_level():
    target=Target("x",TargetType.MODEL,invoke=lambda prompt:"refused");a=AdaptiveAttackPlanner(target,config=AdaptiveConfig(max_steps=4,max_depth=2,seed=99)).run(StaticAttack("hello"),"objective");b=AdaptiveAttackPlanner(target,config=AdaptiveConfig(max_steps=4,max_depth=2,seed=99)).run(StaticAttack("hello"),"objective");assert ReplayEngine().prompts(a.trace)==ReplayEngine().prompts(b.trace)
def test_evidence_digest_is_stable():
    store=EvidenceStore();record=store.add("response",response="hello",score=.2);assert len(record.digest)==64 and store.export()[0]["digest"]==record.digest
