import math,pytest
from ai_auditor import Scanner,Target
from ai_auditor.adapters import hardened_agent,vulnerable_agent
from ai_auditor.replay import ReplayEngine
from ai_auditor.rl import Episode,compare_checkpoints
from ai_auditor.stats import compare_reports,fisher_exact,holm,wilson
def test_wilson_known_values():
    lo,hi=wilson(0,10);assert lo==0.0 and .25<hi<.32
    lo,hi=wilson(50,100);assert math.isclose(lo,.404,abs_tol=.005) and math.isclose(hi,.596,abs_tol=.005) and wilson(0,0)==(0.0,1.0)
def test_fisher_exact_matches_reference():
    assert math.isclose(fisher_exact(8,10,1,6),.03497,abs_tol=1e-4) and fisher_exact(5,10,5,10)==pytest.approx(1.0) and fisher_exact(0,0,1,2)==1.0
def test_holm_is_monotone_and_bounded():
    adj=holm([.01,.04,.03]);assert adj==pytest.approx([.03,.06,.06]) and all(a<=1 for a in adj)
def _target(fn):return Target("t",invoke=fn,capabilities=["system","tools"])
def test_compare_reports_flags_improvement_not_regression():
    bad=Scanner(_target(vulnerable_agent),converters=["identity"],trials=3).run();good=Scanner(_target(hardened_agent),converters=["identity"],trials=3).run();assert compare_reports(bad,good)["regressions"]==[] and compare_reports(bad,good)["overall"]["delta"]<0 and compare_reports(good,bad)["regressions"]
def test_replay_reproduces_then_detects_a_fix():
    report=Scanner(_target(vulnerable_agent),converters=["identity"]).run();same=ReplayEngine().replay(report,_target(vulnerable_agent));assert same.replayed>0 and same.rate==1.0 and all(f.reproducibility==1.0 for f in report.findings);fixed=ReplayEngine().replay(report,_target(lambda prompt,system=None,tools=None:"no"));assert fixed.rate==0.0 and all(f.reproducibility==0.0 for f in report.findings)
def test_rl_checkpoint_comparison_detects_exploitation():
    base=[Episode(reward=.5+.01*i,true_score=.5+.01*i) for i in range(30)];tuned=[Episode(reward=.9+.003*i,true_score=.3+.01*i) for i in range(30)];res=compare_checkpoints(base,tuned,seed=1);assert "TUNED_EXPLOIT_RATE_HIGHER" in res.flags and res.tuned_exploit_rate>res.base_exploit_rate and compare_checkpoints(base,base,seed=1).flags==[]
    with pytest.raises(ValueError):compare_checkpoints([],base)
