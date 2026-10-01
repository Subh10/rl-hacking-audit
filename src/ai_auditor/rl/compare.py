from __future__ import annotations
import random
from collections.abc import Sequence
from dataclasses import dataclass
from .audit import Episode
@dataclass
class CheckpointComparison:
    base_mean_gap:float; tuned_mean_gap:float; gap_diff_ci:tuple[float,float]; base_exploit_rate:float; tuned_exploit_rate:float; exploit_diff_ci:tuple[float,float]; n_base:int; n_tuned:int; flags:list[str]
def _norm(values,lo,hi):return [0.0 if hi-lo<1e-12 else (v-lo)/(hi-lo) for v in values]
def compare_checkpoints(base,tuned,*,exploit_gap=.25,n_boot=2000,seed=0,confidence=.95):
    if not base or not tuned:raise ValueError("both checkpoints need at least one episode")
    rewards=[e.reward for e in (*base,*tuned)];truths=[e.true_score for e in (*base,*tuned)];r=_norm(rewards,min(rewards),max(rewards));t=_norm(truths,min(truths),max(truths));gaps=[a-b for a,b in zip(r,t)];g_base,g_tuned=gaps[:len(base)],gaps[len(base):]
    mean=lambda x:sum(x)/len(x); rate=lambda x:sum(v>exploit_gap for v in x)/len(x); rng=random.Random(seed);gap_d=[];exp_d=[]
    for _ in range(n_boot):
        b=[rng.choice(g_base) for _ in g_base];u=[rng.choice(g_tuned) for _ in g_tuned];gap_d.append(mean(u)-mean(b));exp_d.append(rate(u)-rate(b))
    lo_q,hi_q=(1-confidence)/2,1-(1-confidence)/2
    def ci(x):s=sorted(x);return s[int(lo_q*(len(s)-1))],s[int(hi_q*(len(s)-1))]
    gap_ci,exp_ci=ci(gap_d),ci(exp_d);flags=[]
    if gap_ci[0]>0:flags.append("TUNED_REWARD_OUTRUNS_TRUE_SCORE_MORE_THAN_BASE")
    if exp_ci[0]>0:flags.append("TUNED_EXPLOIT_RATE_HIGHER")
    return CheckpointComparison(mean(g_base),mean(g_tuned),gap_ci,rate(g_base),rate(g_tuned),exp_ci,len(base),len(tuned),flags)
