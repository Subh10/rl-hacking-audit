from __future__ import annotations
from ..scan.models import ScanReport
from ..stats.compare import compare_reports
def _pct(x):return f"{x:.0%}"
def to_markdown(report,baseline=None):
    o=report.overall(); lines=[f"# AI Auditor report - `{report.meta['target']}`","",f"**Overall attack success rate: {_pct(o['asr'])}** ({o['k']}/{o['n']} attempts, 95% CI {_pct(o['ci_low'])}-{_pct(o['ci_high'])}) | findings: {len(report.findings)} | seed {report.meta['seed']} | evidence root `{report.evidence_root[:16]}`",""]
    if o["errors"]:lines += [f"> {o['errors']} attempt(s) errored and are excluded from the rates above.",""]
    if report.findings:
        lines += ["## Findings","","| Severity | Scenario | ASR | 95% CI | Top converters |","|---|---|---|---|---|"]
        for f in report.findings:
            imp=f.impact; conv=", ".join(list(imp.get("successful_converters",{}))[:3]); lines.append(f"| {f.severity.name} | {f.scenario_id} - {f.title} | {_pct(imp['asr'])} ({imp['successes']}/{imp['attempts']}) | {_pct(imp['ci95'][0])}-{_pct(imp['ci95'][1])} | {conv} |")
        lines.append("")
    else:lines += ["No findings. This does **not** prove the target is safe; it only means these scenarios did not succeed at this sample size.",""]
    lines += ["## By converter","","| Converter | ASR | Attempts |","|---|---|---|"]+[f"| {c} | {_pct(s['asr'])} | {s['n']} |" for c,s in report.converter_stats().items()]
    if report.skipped:lines += ["","## Skipped scenarios",""]+[f"- `{k}`: {v}" for k,v in report.skipped.items()]
    if baseline is not None:
        cmp=compare_reports(baseline,report); lines += ["","## Comparison with baseline","",f"Overall ASR {_pct(cmp['overall']['base_asr'])} -> {_pct(cmp['overall']['new_asr'])} (Fisher p={cmp['overall']['p']:.3g}). Significant regressions: {', '.join(cmp['regressions']) or 'none'}."]
    return "\n".join(lines)+"\n"
