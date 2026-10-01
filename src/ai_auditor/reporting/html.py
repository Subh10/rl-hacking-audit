from __future__ import annotations
from html import escape
_CSS="""body{font:15px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:980px;padding:0 1rem;color:#1b1f24}
h1{font-size:1.5rem}h2{margin-top:2rem;font-size:1.15rem}table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #d8dee4;vertical-align:top}
.bar{background:#eaeef2;border-radius:4px;height:10px;width:160px;position:relative}
.bar>i{display:block;height:10px;border-radius:4px;background:#cf222e}
.sev{font-weight:600}.CRITICAL,.HIGH{color:#cf222e}.MEDIUM{color:#9a6700}.LOW,.INFO{color:#57606a}
pre{background:#f6f8fa;padding:.6rem;border-radius:6px;overflow:auto;white-space:pre-wrap}
.muted{color:#57606a;font-size:.9rem}"""
def _bar(asr):return f'<div class="bar"><i style="width:{asr*100:.0f}%"></i></div>'
def to_html(report):
    o=report.overall();e=escape;rows=[]
    for sid,st in report.scenario_stats().items():
        meta=report.scenarios.get(sid,{});rows.append(f"<tr><td>{e(sid)}</td><td>{e(meta.get('title',''))}</td><td class='sev {e(meta.get('severity',''))}'>{e(meta.get('severity',''))}</td><td>{_bar(st['asr'])}{st['asr']:.0%} <span class='muted'>({st['k']}/{st['n']}, CI {st['ci_low']:.0%}-{st['ci_high']:.0%})</span></td></tr>")
    findings=[]
    for f in report.findings:
        ev="".join(f"<p class='muted'>{e(x['attempt_id'])} via <b>{e(x['converter'])}</b> - {e('; '.join(x['reasons']))}</p><pre>{e(x['response'][:500])}</pre>" for x in f.evidence[:2]);fix="".join(f"<li>{e(r)}</li>" for r in f.remediation);findings.append(f"<h3><span class='sev {f.severity.name}'>{f.severity.name}</span> {e(f.scenario_id or '')} - {e(f.title)}</h3><p class='muted'>confidence {f.confidence:.2f} | fingerprint {e(f.fingerprint)}</p>{ev}<ul>{fix}</ul>")
    skipped="".join(f"<li><code>{e(k)}</code>: {e(v)}</li>" for k,v in report.skipped.items())
    return f"<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>AI Auditor - {e(str(report.meta['target']))}</title><style>{_CSS}</style><h1>AI Auditor report: <code>{e(str(report.meta['target']))}</code></h1><p><b>Overall attack success rate {o['asr']:.0%}</b> ({o['k']}/{o['n']} attempts, 95% CI {o['ci_low']:.0%}-{o['ci_high']:.0%}). Findings: {len(report.findings)}. Seed {e(str(report.meta['seed']))}. Evidence root <code>{report.evidence_root[:16]}</code>.</p><p class='muted'>A clean report is not proof of safety; it only reflects the scenarios and sample size used.</p><h2>Scenarios</h2><table><tr><th>ID</th><th>Title</th><th>Severity</th><th>ASR</th></tr>{''.join(rows)}</table><h2>Findings</h2>{''.join(findings) or '<p>No findings.</p>'}{'<h2>Skipped</h2><ul>'+skipped+'</ul>' if skipped else ''}</html>"
