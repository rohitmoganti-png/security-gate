"""Render security-report.json as a one-page security dashboard (self-contained HTML).

Used for security-report.html (CLI --html; the PR's "Security Report" link).

Layout, top to bottom (the pattern of quality-gate / security-overview dashboards):
  header (repo, PR, commit, run) → verdict + key numbers → 3 charts → checks table →
  findings table (details on click) → collapsed extras (AI review, changed files, run, legend).

No JavaScript, no external files: charts are inline SVG / CSS, so the page opens anywhere
(GitHub artifact, S3, offline) and loads nothing from third parties.

SECURITY: the report contains text from the scanned (untrusted) change: code lines,
messages, AI reasoning. EVERYTHING is HTML-escaped; links are only built from the
repository/commit metadata and URL-quoted paths.
"""

from __future__ import annotations

import math
from html import escape
from urllib.parse import quote

WHAT_IT_CHECKS = {
    "Secrets": "Passwords, API keys, tokens and private keys written into the code.",
    "Risky code": "Known vulnerable code patterns (injection, unsafe deserialization, hardcoded signing secrets, …).",
    "AI code smells": "Mistakes AI assistants often make: TLS off, SQL from strings, shell=True, debug on, and so on.",
    "Fake packages": "New dependencies that don't exist, are known malware, or imitate popular packages.",
    "Dependency CVEs": "Known published vulnerabilities in new or upgraded dependency versions.",
    "Infrastructure": "Misconfigured Terraform, Kubernetes, Dockerfiles and CI workflows.",
    "AI review": "Logic flaws scanners can't see (e.g. users reading other users' data): found by an AI Hunter, confirmed by an independent AI Verifier.",
}
HOW_TO_FIX = {
    "Secrets": "Delete the value from the code, ROTATE the key (it is exposed in git history), and load it from an environment variable or secrets manager.",
    "Risky code": "Follow the rule's advice below; use the safe API (parameterized queries, safe loaders, keys from config).",
    "AI code smells": "Replace the shortcut with the safe version described in the message.",
    "Fake packages": "Remove the package or correct the name to the real, well-known package. Never install it to 'try it'.",
    "Dependency CVEs": "Upgrade to the fixed version shown.",
    "Infrastructure": "Restrict the setting as described (see the linked guideline).",
    "AI review": "Apply the suggested fix, e.g. add the missing ownership/permission check.",
}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

SEVERITIES = ("critical", "high", "medium", "low")
STATUS_LABEL = {"PASS": "Passed", "WARN": "Warning", "FAIL": "Failed", "N/A": "Not applicable", "ERROR": "Error"}


def render(report: dict) -> str:
    run = report.get("run", {})
    checks = report.get("checks", [])
    findings = [(c, f) for c in checks for f in c.get("findings", [])]
    findings.sort(key=lambda cf: (not cf[1].get("blocking"), SEV_ORDER.get(cf[1].get("severity"), 9)))
    ai = next((c for c in checks if c.get("name") == "AI review"), None)

    body = [
        _header(report, run),
        '<section class="hero">',
        _verdict(report),
        _kpis(report, checks, findings, ai),
        "</section>",
        '<section class="charts">',
        _card("Findings by severity", _donut(findings)),
        _card("Findings per check", _bars(checks)),
        _card("AI review funnel", _funnel(ai)),
        "</section>",
        _card("Checks", _checks_table(checks), wide=True),
        _card(f"Findings ({len(findings)})", _findings_table(findings, ai, run), wide=True),
        '<section class="extras">',
        _ai_details(ai),
        _changed_files(report.get("changed_files", []), run),
        _run_details(report, run),
        _legend(),
        "</section>",
    ]
    return _page("\n".join(body), report)


# ---------- top ----------


def _header(report: dict, run: dict) -> str:
    repo = run.get("repository") or "local run"
    where = []
    if run.get("pull_request"):
        pr = f"PR #{int(run['pull_request'])}"
        where.append(_link(f"{_repo_url(run)}/pull/{int(run['pull_request'])}", pr) if _repo_url(run) else pr)
    if run.get("branch"):
        where.append(escape(run["branch"]))
    sha = run.get("head_sha") or ""
    if sha and _repo_url(run):
        where.append(_link(f"{_repo_url(run)}/commit/{sha}", sha[:7]))
    elif sha:
        where.append(f"<code>{escape(sha[:7])}</code>")
    meta = [escape(run.get("generated_at", "").replace("T", " ").replace("+00:00", " UTC"))]
    if run.get("actor"):
        meta.append(f"by {escape(run['actor'])}")
    meta.append(f"{float(report.get('duration_seconds') or 0):.0f} s scan")
    if run.get("run_url"):
        meta.append(_link(run["run_url"], "workflow run ↗"))
    return (
        '<header class="top"><div><div class="brand">Security Gate · scan report</div>'
        f'<h1>{escape(repo)}</h1><div class="where">{" · ".join(where)}</div></div>'
        f'<div class="meta">{" · ".join(meta)}</div></header>'
    )


def _verdict(report: dict) -> str:
    code, n = report.get("exit_code"), int(report.get("blocking_count") or 0)
    if code == 2:
        cls, word, line = "error", "ERROR", "A check could not run, so the gate failed closed. See Checks."
    elif code == 1:
        cls, word, line = "fail", "BLOCKED", f"{n} blocking issue{'s' if n != 1 else ''}: fix before merging."
    else:
        cls, word = "pass", "PASSED"
        line = "No blocking issues." + (" Report-only mode: nothing blocks." if report.get("mode") == "report" else "")
    return (
        f'<div class="verdict {cls}"><div class="vlabel">Quality gate</div>'
        f'<div class="vword">{word}</div><div class="vline">{escape(line)}</div>'
        f'<div class="vmode">mode: {escape(report.get("mode", "enforce"))}</div></div>'
    )


def _kpis(report: dict, checks: list[dict], findings: list, ai: dict | None) -> str:
    counts = {s: sum(1 for _, f in findings if f.get("severity") == s) for s in SEVERITIES}
    tiles = [
        f'<div class="kpi sev-{s}"><div class="knum">{counts[s]}</div><div class="klab">{s.title()}</div></div>'
        for s in SEVERITIES
    ]
    status = [c.get("status") for c in checks]
    applicable = [s for s in status if s != "N/A"]
    new = sum(1 for _, f in findings if f.get("new"))
    details = (ai or {}).get("details") or {}
    cost = details.get("cost_usd")
    if details:
        ai_line = f"{int(details.get('calls', 0))} call(s) · " + (
            f"${cost:.3f}" if isinstance(cost, (int, float)) else "cost n/a"
        )
        ai_sub = _short_model(details)
    else:
        ai_line = "Error" if (ai or {}).get("error") else "Skipped"
        ai_sub = (ai or {}).get("error") or (ai or {}).get("not_applicable") or "not run"
    stats = [
        ("Checks passed", f"{status.count('PASS') + status.count('WARN')}/{len(applicable)}",
         f"{status.count('FAIL') + status.count('ERROR')} failed · {status.count('N/A')} not applicable"),
        ("New issues", str(new), f"{len(findings) - new} pre-existing"),
        ("AI review", ai_line, ai_sub),
        ("Scan time", f"{float(report.get('duration_seconds') or 0):.0f} s", f"{len(checks)} checks"),
    ]  # fmt: skip
    stat_html = "".join(
        f'<div class="stat"><div class="slab">{escape(a)}</div><div class="snum">{b}</div>'
        f'<div class="ssub">{escape(c)}</div></div>'
        for a, b, c in stats
    )
    return f'<div class="kpis"><div class="sevrow">{"".join(tiles)}</div><div class="stats">{stat_html}</div></div>'


# ---------- charts ----------


def _donut(findings: list) -> str:
    counts = [(s, sum(1 for _, f in findings if f.get("severity") == s)) for s in SEVERITIES]
    total = sum(n for _, n in counts)
    r, c = 52, 2 * math.pi * 52
    arcs, offset = [], 0.0
    for sev, n in counts:
        if not n:
            continue
        length = c * n / total
        arcs.append(
            f'<circle class="arc sev-{sev}" cx="70" cy="70" r="{r}" stroke-dasharray="{length:.2f} {c - length:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}"><title>{sev}: {n}</title></circle>'
        )
        offset += length
    ring = f'<circle class="arc empty" cx="70" cy="70" r="{r}"/>' if not total else ""
    legend = "".join(
        f'<li><span class="dot sev-{s}"></span>{s.title()}<b>{n}</b></li>' for s, n in counts
    )
    return (
        '<div class="donut"><svg viewBox="0 0 140 140" role="img" aria-label="Findings by severity">'
        f'<g transform="rotate(-90 70 70)">{ring}{"".join(arcs)}</g>'
        f'<text x="70" y="68" class="dtotal">{total}</text><text x="70" y="88" class="dsub">findings</text></svg>'
        f'<ul class="dlegend">{legend}</ul></div>'
    )


def _bars(checks: list[dict]) -> str:
    most = max([len(c.get("findings", [])) for c in checks] + [1])
    rows = []
    for c in checks:
        n = len(c.get("findings", []))
        st = c.get("status", "N/A")
        rows.append(
            f'<div class="brow"><span class="bname">{escape(c.get("name", ""))}</span>'
            f'<span class="btrack"><span class="bfill st-{_cls(st)}" style="width:{100 * n / most:.0f}%"></span></span>'
            f'<span class="bval">{n}</span></div>'
        )
    return f'<div class="bars">{"".join(rows)}</div>'


def _funnel(ai: dict | None) -> str:
    details = (ai or {}).get("details") or {}
    if not details:
        reason = (ai or {}).get("not_applicable") or (ai or {}).get("error") or "AI review did not run"
        return f'<p class="muted center">{escape(reason)}</p>'
    verdicts = [v.get("verdict") for v in details.get("verdicts", [])]
    steps = [
        ("Proposed by Hunter", int(details.get("candidates", 0)), "cand"),
        ("Confirmed", verdicts.count("confirmed"), "conf"),
        ("Needs human review", verdicts.count("needs_validation"), "review"),
        ("Rejected by Verifier", verdicts.count("rejected"), "rej"),
    ]
    most = max([n for _, n, _ in steps] + [1])
    rows = "".join(
        f'<div class="frow"><span class="fname">{a}</span><span class="ftrack">'
        f'<span class="ffill f-{k}" style="width:{max(100 * n / most, 2 if n else 0):.0f}%"></span></span>'
        f'<span class="fval">{n}</span></div>'
        for a, n, k in steps
    )
    fallback = any(c.get("fallback_used") for c in details.get("ai_calls", []))
    foot = (
        f'{int(details.get("calls", 0))} AI call(s) · {int(details.get("input_tokens", 0)):,} in / '
        f'{int(details.get("output_tokens", 0)):,} out tokens · {escape(_short_model(details))}'
        + (' · <span class="tag warn">fallback used</span>' if fallback else "")
    )
    return f'<div class="funnel">{rows}</div><p class="foot">{foot}</p>'


# ---------- tables ----------


def _checks_table(checks: list[dict]) -> str:
    slowest = max([float(c.get("seconds") or 0) for c in checks] + [0.001])
    rows = []
    for i, c in enumerate(checks, 1):
        st = c.get("status", "N/A")
        secs = float(c.get("seconds") or 0)
        note = c.get("error") or c.get("not_applicable") or ""
        note_html = f'<div class="muted small">{escape(note)}</div>' if note else ""
        rows.append(
            f"<tr><td class='num'>{i}</td><td><b>{escape(c.get('name', ''))}</b>"
            f"<div class='muted small'>{escape(WHAT_IT_CHECKS.get(c.get('name', ''), ''))}</div></td>"
            f"<td class='muted small'>{escape(c.get('tool', ''))}</td>"
            f"<td>{_pill(st)}{note_html}</td>"
            f"<td class='num'>{len(c.get('findings', []))}</td>"
            f"<td class='time'><span class='tbar'><span style='width:{100 * secs / slowest:.0f}%'></span></span>"
            f"<span class='small muted'>{secs:.1f} s</span></td></tr>"
        )
    return (
        "<div class='tscroll'><table class='checks'><thead><tr><th>#</th><th>Check</th><th>Tool</th><th>Status</th>"
        f"<th>Findings</th><th>Time</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )


def _findings_table(findings: list, ai: dict | None, run: dict) -> str:
    if not findings:
        return '<p class="empty">No findings in this change.</p>'
    verdicts = {v.get("location"): v for v in ((ai or {}).get("details") or {}).get("verdicts", [])}
    items = []
    for c, f in findings:
        title, _, rest = (f.get("message") or "").partition(" CONFIRMED by independent verifier")
        v = verdicts.get(f"{f.get('path')}:{f.get('line')}") if c.get("name") == "AI review" else None
        body = [f"<dl><dt>Check</dt><dd>{escape(c.get('name', ''))} <span class='muted'>({escape(f.get('rule', ''))})</span></dd>"]
        if v:
            body.append(f"<dt>Why it matters</dt><dd>{escape(v.get('reasoning') or '')}</dd>")
            body.append(f"<dt>Data flow</dt><dd><code>{escape(' → '.join(v.get('trace') or []))}</code></dd>")
            body.append(
                f"<dt>Rating</dt><dd>likelihood {escape(str(v.get('likelihood')))} × impact "
                f"{escape(str(v.get('impact')))} → {escape(str(v.get('severity')))}</dd>"
            )
            body.append(f"<dt>How to fix</dt><dd>{escape(v.get('suggested_fix') or HOW_TO_FIX.get('AI review', ''))}</dd>")
        else:
            if f.get("evidence"):
                body.append(f"<dt>Evidence</dt><dd><pre>{escape(f['evidence'])}</pre></dd>")
            body.append(f"<dt>How to fix</dt><dd>{escape(HOW_TO_FIX.get(c.get('name', ''), ''))}</dd>")
        body.append("</dl>")
        state = ('<span class="tag fail">blocking</span>' if f.get("blocking") else '<span class="tag">not blocking</span>')
        age = '<span class="tag new">new</span>' if f.get("new") else '<span class="tag">pre-existing</span>'
        items.append(
            f'<details class="frow-d"><summary>{_sev(f.get("severity"))}'
            f'<span class="fcheck">{escape(c.get("name", ""))}</span>'
            f'<span class="floc">{_location(f, run)}</span>'
            f'<span class="ftitle">{escape(title.strip())}</span><span class="fstate">{age}{state}</span>'
            f'</summary><div class="fbody">{"".join(body)}</div></details>'
        )
    head = (
        '<div class="fhead"><span>Severity</span><span>Check</span><span>Location</span>'
        "<span>Issue</span><span>Status</span></div>"
    )
    return f'<div class="findings">{head}{"".join(items)}</div><p class="muted small">Click a row for details and how to fix it.</p>'


# ---------- collapsed extras ----------


def _ai_details(ai: dict | None) -> str:
    details = (ai or {}).get("details") or {}
    if not details:
        return ""
    calls = "".join(
        f"<tr><td><code>{escape(str(x.get('call_id') or '-'))}</code></td><td>{escape(str(x.get('model') or ''))}</td>"
        f"<td class='num'>{'$%.4f' % x['cost_usd'] if isinstance(x.get('cost_usd'), (int, float)) else '-'}</td>"
        f"<td>{'yes' if x.get('fallback_used') else 'no'}</td></tr>"
        for x in details.get("ai_calls", [])
    )
    others = "".join(
        f"<li>{_pill_word(v.get('verdict'))} <b>{escape(v.get('title') or '')}</b> "
        f"<span class='muted'>({escape(v.get('location') or '')})</span>: {escape(v.get('reasoning') or '')}</li>"
        for v in details.get("verdicts", [])
        if v.get("verdict") != "confirmed"
    )
    notes = "".join(f"<li>{escape(n)}</li>" for n in (ai or {}).get("notes", []))
    return (
        "<details class='extra'><summary>AI review details</summary>"
        f"<p><b>Provider:</b> {escape(str(details.get('provider')))} · <b>model:</b> {escape(str(details.get('model')))} · "
        f"<b>files reviewed:</b> {escape(', '.join(details.get('files_reviewed', [])))}</p>"
        + (
            "<table><thead><tr><th>Call ID (matches the LiteLLM log)</th><th>Model that answered</th>"
            f"<th>Cost</th><th>Fallback</th></tr></thead><tbody>{calls}</tbody></table>"
            if calls
            else ""
        )
        + (f"<h4>Not confirmed</h4><ul>{others}</ul>" if others else "")
        + (f"<h4>Notes</h4><ul>{notes}</ul>" if notes else "")
        + "</details>"
    )


def _changed_files(files: list[dict], run: dict) -> str:
    rows = "".join(
        f"<tr><td>{_location({'path': x.get('path', ''), 'line': 0}, run)}</td><td>{escape(x.get('status', ''))}</td>"
        f"<td class='num'>{int(x.get('lines_changed') or 0)}</td></tr>"
        for x in files
    )
    return (
        f"<details class='extra'><summary>Changed files ({len(files)})</summary>"
        "<table><thead><tr><th>File</th><th>Change</th><th>Lines</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></details>"
    )


def _run_details(report: dict, run: dict) -> str:
    rows = [
        ("Repository", escape(run.get("repository") or "-")),
        ("Event", escape(run.get("event") or "-")),
        ("Branch", escape(run.get("branch") or "-")),
        ("Pull request", escape(str(run.get("pull_request") or "-"))),
        ("Base → head", f"<code>{escape((run.get('base_sha') or '-')[:12])}</code> → <code>{escape((run.get('head_sha') or '-')[:12])}</code>"),
        ("Triggered by", escape(run.get("actor") or "-")),
        ("Run", _link(run["run_url"], f"{run.get('run_id')} (attempt {run.get('run_attempt') or 1})") if run.get("run_url") else "-"),
        ("Generated", escape(run.get("generated_at") or "-")),
        ("Gate version", escape(str(report.get("version") or "-"))),
    ]  # fmt: skip
    body = "".join(f"<tr><th>{a}</th><td>{b}</td></tr>" for a, b in rows)
    return f"<details class='extra'><summary>About this run</summary><table class='kv'>{body}</table></details>"


def _legend() -> str:
    return (
        "<details class='extra'><summary>How to read this report</summary><ul>"
        "<li><b>Quality gate</b>: BLOCKED means at least one <i>new</i> HIGH or CRITICAL issue in this change "
        "(the merge should wait). ERROR means a check could not run, so the gate refused to guess.</li>"
        "<li><b>New vs pre-existing</b>: only issues on lines this change touched are new. Pre-existing "
        "issues are shown but never block.</li>"
        "<li><b>AI review</b>: an AI Hunter proposes problems; a separate AI Verifier must confirm each one "
        "before it counts. Severity comes from likelihood × impact, computed in code.</li>"
        "<li><b>Not applicable</b>: the check had nothing to look at (e.g. no dependency files changed).</li>"
        "</ul></details>"
    )


# ---------- helpers ----------


def _repo_url(run: dict) -> str:
    if not run.get("repository"):
        return ""
    return f"{run.get('server_url', 'https://github.com')}/{quote(run['repository'])}"


def _location(f: dict, run: dict) -> str:
    path, line = f.get("path", ""), int(f.get("line") or 0)
    label = f"{path}:{line}" if line else path
    if _repo_url(run) and run.get("head_sha"):
        url = f"{_repo_url(run)}/blob/{quote(run['head_sha'])}/{quote(path)}" + (f"#L{line}" if line else "")
        return _link(url, label)
    return f"<code>{escape(label)}</code>"


def _link(url: str, text: str) -> str:
    if not url.startswith(("https://", "http://")):
        return escape(text)
    return f'<a href="{escape(url, quote=True)}" target="_blank" rel="noopener noreferrer">{escape(text)}</a>'



def _card(title: str, inner: str, wide: bool = False) -> str:
    return f'<section class="card{" wide" if wide else ""}"><h2>{escape(title)}</h2>{inner}</section>'


def _cls(status: str) -> str:
    return {"PASS": "pass", "WARN": "warn", "FAIL": "fail", "N/A": "na", "ERROR": "error"}.get(status, "na")


def _pill(status: str) -> str:
    return f'<span class="pill st-{_cls(status)}">{escape(STATUS_LABEL.get(status, status))}</span>'


def _pill_word(verdict: str | None) -> str:
    return f'<span class="pill st-{"warn" if verdict == "needs_validation" else "na"}">{escape(str(verdict))}</span>'


def _sev(severity: str | None) -> str:
    s = (severity or "none").lower()
    return f'<span class="sev sev-{escape(s)}">{escape(s.upper())}</span>'


def _short_model(details: dict) -> str:
    models = {str(c.get("model") or "") for c in details.get("ai_calls", [])} or {str(details.get("model") or "")}
    names = sorted(m.split("anthropic.")[-1].split("/")[-1] for m in models if m)
    return ", ".join(names) if names else ""


def _page(body: str, report: dict) -> str:
    title = f"Security report · {report.get('run', {}).get('repository') or 'local'} · {report.get('result', '')}"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title><style>{CSS}</style></head>
<body><main>{body}<footer>Generated by Security Gate {escape(str(report.get("version", "")))}. Self-contained page: no scripts, nothing loaded from the internet.</footer></main></body></html>"""


CSS = """
:root{--bg:#f5f7fa;--card:#fff;--text:#1f2937;--muted:#6b7280;--line:#e5e7eb;--track:#eef1f5;
--pass:#16a34a;--warn:#d97706;--fail:#dc2626;--error:#7c3aed;--na:#9ca3af;
--critical:#991b1b;--high:#ea580c;--medium:#ca8a04;--low:#2563eb}
@media (prefers-color-scheme:dark){:root{--bg:#0f141b;--card:#171e27;--text:#e5e7eb;--muted:#9aa4b2;
--line:#2a3441;--track:#222b36;--critical:#f87171;--high:#fb923c;--medium:#facc15;--low:#60a5fa}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1680px;margin:0 auto;padding:24px clamp(16px,2.5vw,40px) 40px}a{color:inherit}
code,pre{font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}pre{white-space:pre-wrap;margin:0}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;margin-bottom:16px}
.brand{font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
h1{font-size:22px;margin:2px 0}.where,.meta{color:var(--muted);font-size:13px}
.hero{display:grid;grid-template-columns:minmax(260px,22%) 1fr;gap:16px;margin-bottom:16px}
.verdict{border-radius:12px;padding:18px 20px;color:#fff}.verdict.fail{background:var(--fail)}
.verdict.pass{background:var(--pass)}.verdict.error{background:var(--error)}
.vlabel{font-size:12px;text-transform:uppercase;letter-spacing:.08em;opacity:.85}
.vword{font-size:34px;font-weight:800;letter-spacing:.02em;margin:4px 0}.vline{font-size:14px}
.vmode{font-size:12px;opacity:.8;margin-top:10px}
.kpis{display:grid;gap:12px}.sevrow,.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.kpi,.stat,.card{background:var(--card);border:1px solid var(--line);border-radius:12px}
.kpi{padding:12px 14px;border-top:4px solid var(--c)}.knum{font-size:28px;font-weight:700;color:var(--c)}
.klab{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.sev-critical{--c:var(--critical)}.sev-high{--c:var(--high)}.sev-medium{--c:var(--medium)}.sev-low{--c:var(--low)}
.stat{padding:10px 14px}.slab{font-size:12px;color:var(--muted)}.snum{font-size:18px;font-weight:700}
.ssub{font-size:12px;color:var(--muted)}
.charts{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:16px}
.card{padding:14px 16px;margin-bottom:16px;min-width:0}.tscroll{overflow-x:auto}
.hero>*,.charts>*,.kpis>*{min-width:0}.charts .card{margin:0}
h2{font-size:14px;margin:0 0 12px;font-weight:650}
.donut{display:flex;align-items:center;gap:16px}.donut svg{width:140px;height:140px;flex:none}
.arc{fill:none;stroke:var(--c);stroke-width:18}.arc.empty{stroke:var(--track)}
.dtotal{font-size:28px;font-weight:700;text-anchor:middle;fill:var(--text)}
.dsub{font-size:11px;text-anchor:middle;fill:var(--muted)}
.dlegend{list-style:none;margin:0;padding:0;font-size:13px}.dlegend li{display:flex;gap:8px;align-items:center;margin:4px 0}
.dlegend b{margin-left:auto;padding-left:12px}.dot{width:10px;height:10px;border-radius:50%;background:var(--c)}
.brow,.frow{display:grid;grid-template-columns:120px 1fr 28px;align-items:center;gap:8px;margin:6px 0;font-size:13px}
.frow{grid-template-columns:150px 1fr 28px}
.btrack,.ftrack,.tbar{display:block;height:10px;background:var(--track);border-radius:6px;overflow:hidden}
.bfill,.ffill,.tbar span{display:block;height:100%;border-radius:6px}
.bval,.fval{text-align:right;font-weight:600}
.st-pass{background:var(--pass)}.st-warn{background:var(--warn)}.st-fail{background:var(--fail)}
.st-error{background:var(--error)}.st-na{background:var(--na)}
.f-cand{background:#64748b}.f-conf{background:var(--fail)}.f-review{background:var(--warn)}.f-rej{background:var(--na)}
.foot{font-size:12px;color:var(--muted);margin:10px 0 0}.center{text-align:center;margin-top:40px}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:var(--muted);font-weight:600;
font-size:12px;text-transform:uppercase;letter-spacing:.04em}th,td{padding:8px;border-bottom:1px solid var(--line);vertical-align:top}
.num{text-align:right;width:1%;white-space:nowrap}.time{white-space:nowrap;width:1%}.tbar{width:80px;display:inline-block;margin-right:8px;vertical-align:middle}
.tbar span{background:#64748b}.muted{color:var(--muted)}.small{font-size:12px}
.pill{display:inline-block;padding:1px 9px;border-radius:999px;color:#fff;font-size:12px;font-weight:600}
.sev{display:inline-block;min-width:74px;text-align:center;padding:1px 8px;border-radius:6px;font-size:11px;
font-weight:700;color:#fff;background:var(--c,var(--na))}
.tag{display:inline-block;padding:0 7px;margin-left:4px;border:1px solid var(--line);border-radius:6px;font-size:11px;color:var(--muted)}
.tag.fail{border-color:var(--fail);color:var(--fail)}.tag.new{border-color:var(--low);color:var(--low)}
.tag.warn{border-color:var(--warn);color:var(--warn)}
.fhead,.findings summary{display:grid;grid-template-columns:90px 120px 190px 1fr 190px;gap:10px;align-items:center}
.fhead{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;padding:0 8px 6px}
.findings details{border-top:1px solid var(--line)}.findings summary{padding:10px 8px;cursor:pointer;list-style:none}
.findings summary::-webkit-details-marker{display:none}.findings summary:hover{background:var(--track)}
.fcheck,.floc{font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ftitle{font-weight:600}
.fstate{text-align:right}.fbody{padding:4px 12px 14px 108px}.fbody dl{margin:0;display:grid;grid-template-columns:130px 1fr;gap:6px 12px}
.fbody dt{color:var(--muted);font-size:12px}.fbody dd{margin:0}
.empty{padding:20px;text-align:center;color:var(--pass);font-weight:600}
.extras{display:grid;gap:10px}.extra{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 16px}
.extra summary{cursor:pointer;font-weight:650}.extra table{margin-top:10px}.kv th{width:160px}
footer{margin-top:24px;font-size:12px;color:var(--muted);text-align:center}
@media (max-width:900px){.hero,.charts{grid-template-columns:1fr}.sevrow,.stats{grid-template-columns:repeat(2,1fr)}
.fhead{display:none}.findings summary{grid-template-columns:1fr;gap:4px}.fstate{text-align:left}.fbody{padding:4px 8px 12px}
.fbody dl{grid-template-columns:1fr}.brow{grid-template-columns:110px 1fr 24px}.frow{grid-template-columns:130px 1fr 24px}
.checks th:nth-child(3),.checks td:nth-child(3),.checks td .muted.small:first-of-type{display:none}
.checks td:nth-child(2) .muted.small{display:none}.top{align-items:flex-start}}
"""
