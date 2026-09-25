"""Render security-report.json as ONE self-contained, responsive HTML page.

Design goals: simple to read at a glance (big verdict, 7 stage tiles, "fix these first"),
with every detail one click away. No JavaScript, no external files: it opens offline.

SECURITY: the report contains text from the scanned (untrusted) change: code lines,
messages, AI reasoning. EVERYTHING is HTML-escaped; links are only built from the
repository/commit metadata and URL-quoted paths.
"""

from __future__ import annotations

from html import escape
from urllib.parse import quote

ICON = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "N/A": "➖", "ERROR": "🛑"}
STATUS_TEXT = {
    "PASS": "Passed: nothing found",
    "WARN": "Warnings only: nothing blocking",
    "FAIL": "Failed: at least one blocking issue",
    "N/A": "Not applicable to this change",
    "ERROR": "Could not run: the gate fails closed",
}
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


def render(report: dict) -> str:
    run = report.get("run", {})
    checks = report.get("checks", [])
    blocking = [(c, f) for c in checks for f in c.get("findings", []) if f.get("blocking")]
    blocked = report.get("exit_code") == 1 or (blocking and report.get("mode") == "enforce")
    errored = report.get("exit_code") == 2

    parts = [_head(), "<body><main>"]
    parts.append(_banner(report, blocked, errored, len(blocking)))
    parts.append(_run_info(report, run))
    parts.append(_pipeline(checks))
    if blocking:
        parts.append(_fix_first(blocking, run))
    parts.append(_all_checks(checks, run))
    ai = next((c for c in checks if c.get("name") == "AI review" and c.get("details")), None)
    if ai:
        parts.append(_ai_section(ai, run))
    parts.append(_changed_files(report.get("changed_files", []), run))
    parts.append(_legend(report))
    parts.append("</main></body></html>")
    return "\n".join(parts)


# ---------- sections ----------


def _banner(report: dict, blocked: bool, errored: bool, n_blocking: int) -> str:
    if errored:
        cls, title = "error", "🛑 GATE ERROR: a check could not run"
        say = "A check could not run, so the gate fails closed. See the stage marked ERROR below."
    elif blocked:
        cls, title = "fail", f"❌ BLOCKED: {n_blocking} blocking issue{'s' if n_blocking != 1 else ''}"
        say = "This change can't be merged yet. Fix the issues under “Fix these first”, then push again."
    elif report.get("blocking_count"):
        cls, title = "warn", f"⚠️ REPORT ONLY: {report['blocking_count']} blocking issue(s) (mode=report)"
        say = "Watch-only mode: these would block in enforce mode. Please fix them soon."
    else:
        cls, title = "pass", "✅ PASSED: no blocking issues"
        say = "No new high or critical security issues. Any warnings below are worth a look but don't block."
    return f'<header class="banner {cls}"><h1>{escape(title)}</h1><p>{escape(say)}</p></header>'


def _run_info(report: dict, run: dict) -> str:
    repo = run.get("repository") or "local repository"
    rows = [
        ("Repository", _link(_repo_url(run), repo)),
        ("Pull request", _link(f"{_repo_url(run)}/pull/{run['pull_request']}", f"#{run['pull_request']}")
         if run.get("pull_request") and _repo_url(run) else "—"),  # fmt: skip
        ("Branch", escape(run.get("branch") or "—")),
        ("Commit", _link(f"{_repo_url(run)}/commit/{run.get('head_sha', '')}", run.get("head_sha", "")[:8])
         if _repo_url(run) else escape(run.get("head_sha", "")[:8])),  # fmt: skip
        ("Event", escape(run.get("event") or "—")),
        ("Author", escape(run.get("actor") or "—")),
        ("When (UTC)", escape(run.get("generated_at") or "—")),
        ("Mode", escape(report.get("mode", ""))),
        ("Scan time", f"{report.get('duration_seconds', 0)} s"),
        ("CI run", _link(run.get("run_url", ""), "open the GitHub Actions log") if run.get("run_url") else "—"),
        ("Gate version", escape(str(report.get("version", "")))),
    ]
    cells = "".join(f"<div><dt>{k}</dt><dd>{v}</dd></div>" for k, v in rows)
    return f'<section><h2>About this run</h2><dl class="meta">{cells}</dl></section>'


def _pipeline(checks: list[dict]) -> str:
    tiles = []
    for i, c in enumerate(checks, 1):
        st = c.get("status", "")
        tiles.append(
            f'<a class="tile s-{_cls(st)}" href="#check-{i}">'
            f'<span class="num">{i}</span><span class="icon">{ICON.get(st, "")}</span>'
            f'<span class="name">{escape(c.get("name", ""))}</span>'
            f'<span class="st">{escape(st)}</span>'
            f'<span class="small">{escape(_summary(c))}</span></a>'
        )
    return (
        '<section><h2>The 7 security stages</h2>'
        '<p class="hint">Click a stage to jump to its details.</p>'
        f'<div class="pipeline">{"".join(tiles)}</div></section>'
    )


def _fix_first(blocking: list[tuple[dict, dict]], run: dict) -> str:
    blocking = sorted(blocking, key=lambda cf: SEV_ORDER.get(cf[1].get("severity", "low"), 9))
    items = []
    for c, f in blocking:
        items.append(
            f'<li class="fix"><div class="fix-head">{_sev(f.get("severity"))}'
            f'<strong>{escape(c.get("name", ""))}</strong> · {_location(f, run)} · '
            f'<code>{escape(f.get("rule", ""))}</code></div>'
            f'<p>{escape(f.get("message", ""))}</p>'
            f'<p class="howto"><b>How to fix:</b> {escape(HOW_TO_FIX.get(c.get("name", ""), ""))}</p></li>'
        )
    return (
        '<section class="urgent"><h2>🔧 Fix these first (they block the merge)</h2>'
        f'<ol class="fixes">{"".join(items)}</ol></section>'
    )


def _all_checks(checks: list[dict], run: dict) -> str:
    blocks = []
    for i, c in enumerate(checks, 1):
        st = c.get("status", "")
        open_attr = " open" if st in ("FAIL", "ERROR", "WARN") else ""
        body = [f'<p class="what"><b>What it checks:</b> {escape(WHAT_IT_CHECKS.get(c.get("name", ""), ""))}</p>',
                f'<p class="small">Tool: <code>{escape(c.get("tool", ""))}</code> · '
                f'{c.get("seconds", 0):.1f} s</p>']  # fmt: skip
        if c.get("error"):
            body.append(f'<p class="err"><b>Could not run:</b> {escape(c["error"])}</p>')
        if c.get("not_applicable"):
            body.append(f"<p><b>Not applicable:</b> {escape(c['not_applicable'])}</p>")
        if c.get("notes"):
            notes = "".join(f"<li>{escape(n)}</li>" for n in c["notes"])
            body.append(f'<ul class="notes">{notes}</ul>')
        findings = sorted(c.get("findings", []), key=lambda f: (SEV_ORDER.get(f.get("severity"), 9), f.get("path", "")))
        if findings:
            body.append('<div class="findings">' + "".join(_finding(f, run) for f in findings) + "</div>")
        elif not c.get("error") and not c.get("not_applicable"):
            body.append("<p>No issues found.</p>")
        blocks.append(
            f'<details id="check-{i}" class="check s-{_cls(st)}"{open_attr}>'
            f'<summary><span class="num">{i}</span> {ICON.get(st, "")} <b>{escape(c.get("name", ""))}</b>'
            f' <span class="pill s-{_cls(st)}">{escape(st)}</span>'
            f' <span class="small">{escape(STATUS_TEXT.get(st, ""))} · {escape(_summary(c))}</span></summary>'
            f'<div class="body">{"".join(body)}</div></details>'
        )
    return f'<section><h2>Every check in detail</h2>{"".join(blocks)}</section>'


def _finding(f: dict, run: dict) -> str:
    tags = [
        '<span class="tag block">BLOCKING</span>' if f.get("blocking") else '<span class="tag">warning</span>',
        '<span class="tag new">new in this change</span>' if f.get("new") else '<span class="tag">pre-existing (not blocking)</span>',
    ]
    evidence = f.get("evidence", "")
    ev_html = ""
    if evidence.startswith(("http://", "https://")):
        ev_html = f'<p class="small">Guideline: {_link(evidence, evidence)}</p>'
    elif evidence:
        ev_html = f"<pre>{escape(evidence)}</pre>"
    return (
        f'<article class="finding">{_sev(f.get("severity"))} {"".join(tags)}'
        f'<div class="loc">{_location(f, run)} · <code>{escape(f.get("rule", ""))}</code></div>'
        f'<p>{escape(f.get("message", ""))}</p>{ev_html}</article>'
    )


def _ai_section(check: dict, run: dict) -> str:
    d = check["details"]
    verdicts = d.get("verdicts", [])
    confirmed = sum(v["verdict"] == "confirmed" for v in verdicts)
    review = sum(v["verdict"] == "needs_validation" for v in verdicts)
    rejected = sum(v["verdict"] == "rejected" for v in verdicts)
    cost = f"${d['cost_usd']:.4f}" if d.get("cost_usd") is not None else "unknown"
    funnel = (
        '<div class="funnel">'
        f'<div><b>{d.get("candidates", 0)}</b><span>proposed by the Hunter</span></div>'
        f'<div class="s-fail"><b>{confirmed}</b><span>confirmed by the Verifier</span></div>'
        f'<div class="s-warn"><b>{review}</b><span>need human review</span></div>'
        f'<div class="s-pass"><b>{rejected}</b><span>rejected (disproved)</span></div></div>'
    )
    cards = []
    for v in verdicts:
        rating = ""
        if v["verdict"] == "confirmed":
            rating = (f'<p><b>Rating:</b> likelihood <b>{escape(v.get("likelihood") or "")}</b> × impact '
                      f'<b>{escape(v.get("impact") or "")}</b> → {_sev(v.get("severity"))}</p>')  # fmt: skip
        blockers = f'<p><b>Unresolved:</b> {escape(v["blockers"])}</p>' if v.get("blockers") else ""
        path, _, line = v.get("location", "").partition(":")
        loc = _location({"path": path, "line": int(line) if line.isdigit() else 1}, run)
        trace = " → ".join(escape(t) for t in v.get("trace", []))
        cards.append(
            f'<article class="finding verdict-{escape(v["verdict"])}">'
            f'<div class="loc"><span class="pill v-{escape(v["verdict"])}">{escape(v["verdict"].replace("_", " "))}</span>'
            f" <b>{escape(v.get('title', ''))}</b> · {loc}</div>"
            f"<p><b>Why:</b> {escape(v.get('reasoning', ''))}</p>{rating}{blockers}"
            f'<p class="small"><b>Code path:</b> {trace}</p>'
            f"<p><b>Suggested fix:</b> {escape(v.get('suggested_fix', ''))}</p></article>"
        )
    invalid = ""
    if d.get("rejected_by_validator"):
        items = "".join(f"<li>{escape(x)}</li>" for x in d["rejected_by_validator"])
        invalid = f'<p class="small"><b>AI output rejected by our plain-code validator:</b></p><ul class="notes">{items}</ul>'
    return (
        '<section><h2>🤖 AI review in detail (Stations 9 + 10)</h2>'
        '<p class="hint">The <b>Hunter</b> proposes possible logic flaws. A separate, independent '
        '<b>Verifier</b> tries to disprove each one. Only <b>confirmed</b> high/critical issues can block; '
        '"needs review" items go to a human and never block.</p>'
        f"{funnel}{''.join(cards) or '<p>The Hunter found nothing to report.</p>'}{invalid}"
        f'<p class="small">Model <code>{escape(d.get("model", ""))}</code> · {d.get("calls", 0)} AI call(s) · '
        f'{d.get("input_tokens", 0)} input + {d.get("output_tokens", 0)} output tokens · estimated cost {cost} · '
        f'files shown to the AI (secrets redacted): {escape(", ".join(d.get("files_reviewed", [])))}</p></section>'
    )


def _changed_files(files: list[dict], run: dict) -> str:
    if not files:
        return ""
    rows = "".join(
        f"<tr><td>{_location({'path': f['path'], 'line': 0}, run)}</td>"
        f"<td>{escape(f.get('status', ''))}</td><td>{f.get('lines_changed', 0)}</td></tr>"
        for f in files
    )
    return (
        '<section><h2>Files changed in this change</h2><table><thead><tr><th>File</th><th>Change</th>'
        f"<th>New/changed lines</th></tr></thead><tbody>{rows}</tbody></table></section>"
    )


def _legend(report: dict) -> str:
    items = "".join(f"<li>{ICON[k]} <b>{k}</b>: {v}</li>" for k, v in STATUS_TEXT.items())
    return (
        '<section class="legend"><h2>How to read this report</h2><ul>'
        f"{items}</ul><p>Only issues that are <b>high or critical</b> AND on lines <b>this change wrote</b> "
        "block the merge. Secrets are always shown masked. Generated by the Security Gate "
        f"v{escape(str(report.get('version', '')))}.</p></section>"
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


def _sev(severity: str | None) -> str:
    s = (severity or "none").lower()
    return f'<span class="sev sev-{escape(s)}">{escape(s.upper())}</span>'


def _cls(status: str) -> str:
    return {"PASS": "pass", "WARN": "warn", "FAIL": "fail", "N/A": "na", "ERROR": "error"}.get(status, "na")


def _summary(c: dict) -> str:
    if c.get("error"):
        return "could not run"
    if c.get("not_applicable"):
        return c["not_applicable"]
    findings = c.get("findings", [])
    if not findings:
        return "no issues"
    n_block = sum(1 for f in findings if f.get("blocking"))
    return f"{len(findings)} finding(s), {n_block} blocking"


def _head() -> str:
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Gate report</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2330;--muted:#5d6675;--line:#e1e5eb;
--pass:#1a7f37;--warn:#b35900;--fail:#cf222e;--na:#6e7781;--error:#8250df;
--pass-bg:#e6f4ea;--warn-bg:#fff3e0;--fail-bg:#ffebe9;--na-bg:#f0f2f4;--error-bg:#f3eefe}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--card:#161b22;--text:#e6edf3;--muted:#9aa4af;--line:#30363d;
--pass-bg:#12261a;--warn-bg:#2b1d0a;--fail-bg:#2d1216;--na-bg:#1f242b;--error-bg:#221a33}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1100px;margin:0 auto;padding:16px}
section,.banner{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:0 0 16px}
h1{margin:0;font-size:1.6rem}h2{margin:0 0 10px;font-size:1.15rem}
.banner.pass{border-left:8px solid var(--pass);background:var(--pass-bg)}
.banner.fail{border-left:8px solid var(--fail);background:var(--fail-bg)}
.banner.warn{border-left:8px solid var(--warn);background:var(--warn-bg)}
.banner.error{border-left:8px solid var(--error);background:var(--error-bg)}
.banner p{margin:6px 0 0;color:var(--muted)}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px 16px;margin:0}
.meta dt{font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}.meta dd{margin:0;word-break:break-all}
.hint,.small{color:var(--muted);font-size:.88rem}
.pipeline{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:10px}
.tile{display:flex;flex-direction:column;gap:2px;padding:12px;border-radius:10px;border:1px solid var(--line);
text-decoration:none;color:var(--text);position:relative}
.tile .num{position:absolute;top:8px;right:10px;color:var(--muted);font-size:.8rem}
.tile .icon{font-size:1.5rem}.tile .name{font-weight:600}.tile .st{font-weight:700;font-size:.85rem}
.s-pass{background:var(--pass-bg)}.s-warn{background:var(--warn-bg)}.s-fail{background:var(--fail-bg)}
.s-na{background:var(--na-bg)}.s-error{background:var(--error-bg)}
.tile.s-fail{border-color:var(--fail)}.tile.s-error{border-color:var(--error)}
.urgent{border:2px solid var(--fail)}.fixes{margin:0;padding-left:20px}.fix{margin:0 0 12px}.fix p{margin:4px 0}
.howto{background:var(--na-bg);padding:6px 10px;border-radius:6px}
details.check{border:1px solid var(--line);border-radius:10px;margin:0 0 10px;background:var(--card)}
details.check>summary{cursor:pointer;padding:12px;list-style:none;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
details.check>summary::-webkit-details-marker{display:none}
details.check .num{display:inline-grid;place-items:center;width:24px;height:24px;border-radius:50%;background:var(--na-bg);font-size:.8rem}
details.check .body{padding:0 14px 12px;border-top:1px solid var(--line)}
.pill{padding:1px 8px;border-radius:999px;font-size:.78rem;font-weight:700;border:1px solid var(--line)}
.pill.s-pass{color:var(--pass)}.pill.s-warn{color:var(--warn)}.pill.s-fail{color:var(--fail)}.pill.s-error{color:var(--error)}
.v-confirmed{color:var(--fail)}.v-needs_validation{color:var(--warn)}.v-rejected{color:var(--pass)}
.finding{border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:8px 0;background:var(--bg)}
.finding p{margin:6px 0}.loc{font-size:.92rem;word-break:break-all}
.sev{display:inline-block;padding:1px 7px;border-radius:5px;font-size:.75rem;font-weight:800;color:#fff;margin-right:6px}
.sev-critical{background:#8b0000}.sev-high{background:var(--fail)}.sev-medium{background:var(--warn)}
.sev-low{background:var(--na)}.sev-none{background:var(--na)}
.tag{display:inline-block;font-size:.72rem;padding:1px 6px;border-radius:5px;border:1px solid var(--line);margin-right:4px;color:var(--muted)}
.tag.block{border-color:var(--fail);color:var(--fail);font-weight:700}.tag.new{color:var(--text)}
pre{white-space:pre-wrap;word-break:break-word;background:var(--na-bg);padding:8px 10px;border-radius:6px;font-size:.85rem;margin:6px 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.88em}
.notes{margin:6px 0;padding-left:18px;color:var(--muted);font-size:.9rem}.err{color:var(--error)}
.funnel{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:10px 0}
.funnel div{border:1px solid var(--line);border-radius:10px;padding:10px;text-align:center}
.funnel b{display:block;font-size:1.6rem}.funnel span{color:var(--muted);font-size:.85rem}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);word-break:break-all}
a{color:#0969da}@media (prefers-color-scheme:dark){a{color:#58a6ff}}
.legend ul{padding-left:18px;margin:6px 0}
</style></head>"""
