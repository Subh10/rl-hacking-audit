from __future__ import annotations
from .intervals import fisher_exact,holm,wilson
def compare_reports(base,new,alpha=0.05):
    b_stats,n_stats=base.scenario_stats(),new.scenario_stats(); ids=sorted(set(b_stats)&set(n_stats)); rows=[]
    for sid in ids:
        b,n=b_stats[sid],n_stats[sid]; rows.append({"scenario_id":sid,"base_asr":b["asr"],"new_asr":n["asr"],"delta":n["asr"]-b["asr"],"base_n":b["n"],"new_n":n["n"],"base_ci":[b["ci_low"],b["ci_high"]],"new_ci":[n["ci_low"],n["ci_high"]],"p":fisher_exact(b["k"],b["n"],n["k"],n["n"]) if b["n"] and n["n"] else 1.0})
    for row,adj in zip(rows,holm([r["p"] for r in rows])):
        row["p_adj"]=adj; significant=adj<alpha; row["verdict"]="regression" if significant and row["delta"]>0 else "improvement" if significant and row["delta"]<0 else "no_significant_change"
    bo,no=base.overall(),new.overall(); overall_p=fisher_exact(bo["k"],bo["n"],no["k"],no["n"]) if bo["n"] and no["n"] else 1.0
    overall_verdict="regression" if overall_p<alpha and no["asr"]>bo["asr"] else "improvement" if overall_p<alpha and no["asr"]<bo["asr"] else "no_significant_change"
    return {"alpha":alpha,"overall":{"base_asr":bo["asr"],"new_asr":no["asr"],"delta":no["asr"]-bo["asr"],"p":overall_p,"verdict":overall_verdict,"base_ci":list(wilson(bo["k"],bo["n"])),"new_ci":list(wilson(no["k"],no["n"]))},"scenarios":rows,"only_in_base":sorted(set(b_stats)-set(n_stats)),"only_in_new":sorted(set(n_stats)-set(b_stats)),"regressions":[r["scenario_id"] for r in rows if r["verdict"]=="regression"]}
