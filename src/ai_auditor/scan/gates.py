from __future__ import annotations
from ..findings.schema import Severity
from ..stats.compare import compare_reports
def evaluate_gates(report,*,fail_on=None,max_asr=None,baseline=None,alpha=.05):
    failures=[]
    if fail_on:
        threshold=Severity.parse(fail_on);hits=[f for f in report.findings if f.severity>=threshold]
        if hits:failures.append(f"{len(hits)} finding(s) at or above {threshold.name}: "+", ".join(sorted({f.scenario_id or f.category for f in hits})))
    if max_asr is not None:
        asr=report.overall()["asr"]
        if asr>max_asr:failures.append(f"overall attack success rate {asr:.1%} exceeds --max-asr {max_asr:.1%}")
    if baseline is not None:
        cmp=compare_reports(baseline,report,alpha)
        if cmp["overall"]["verdict"]=="regression":o=cmp["overall"];failures.append(f"overall attack success rate rose {o['base_asr']:.0%} -> {o['new_asr']:.0%} vs baseline (Fisher p={o['p']:.2g})")
        if cmp["regressions"]:failures.append("statistically significant regression vs baseline in: "+", ".join(cmp["regressions"]))
    return failures
