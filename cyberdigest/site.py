"""Render the digest as a soft-dark newsroom page (hero lead + notable list),
with the members-only encryption gate. Only ciphertext is published when locked."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from .fetch import Item

_TABS = [("daily", "Daily"), ("weekly", "Weekly"), ("monthly", "Monthly")]

# Items are bucketed by .category into ordered sections, each with its own limit,
# so news / healthcare never get crowded out by advisories. Overridable from
# feeds.yaml -> display: {sections: [...], section_limits: {...}}.
_DEFAULT_SECTIONS = [
    ("advisories", "CVE &amp; ADVISORIES"),
    ("intel",      "THREAT ACTOR / INTEL"),
    ("health",     "HEALTHCARE BREACHES"),
    ("news",       "OTHER NEWS"),
]
_DEFAULT_SECTION_LIMITS = {"advisories": 40, "intel": 40, "health": 25, "news": 90}
_DEFAULT_SOURCE_CAP = 10  # max items from one source within a section (diversity guard)


def _resolve_display(display):
    display = display or {}
    secs = display.get("sections")
    if secs:
        sections = [(s["category"], s.get("label", s["category"].upper())) for s in secs]
    else:
        sections = list(_DEFAULT_SECTIONS)
    limits = dict(_DEFAULT_SECTION_LIMITS)
    limits.update(display.get("section_limits", {}) or {})
    cap = display.get("per_source_cap", _DEFAULT_SOURCE_CAP)
    return sections, limits, cap


def _diversify(items: list[Item], limit: int, cap) -> list[Item]:
    """Interleave sources round-robin: the best item from each source first, then the
    second from each, and so on — up to `cap` per source and `limit` overall. Keeps a
    single busy source from filling the whole section while preserving score order."""
    from collections import OrderedDict
    by_src: "OrderedDict[str, list[Item]]" = OrderedDict()
    for it in items:  # items arrive score-sorted, so first-seen = highest-scoring source
        by_src.setdefault(it.source, []).append(it)
    out: list[Item] = []
    r = 0
    while len(out) < limit:
        added = False
        for lst in by_src.values():
            if r < len(lst) and (cap is None or r < cap):
                out.append(lst[r])
                added = True
                if len(out) >= limit:
                    break
        if not added:
            break
        r += 1
    return out
_DOT = {"critical": "#ff8080", "high": "#ffb020", "medium": "#ffd84d", "info": "#7c8699"}
_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "info": "INFO"}
_CODE = re.compile(r"^(CVE-\d{4}-\d+|CVSS.*)$", re.I)


def _esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")




def _ago(dt: datetime) -> str:
    secs = (datetime.now(timezone.utc) - dt).total_seconds()
    if secs < 3600:
        return f"{max(1, int(secs // 60))}m ago"
    if secs < 86400:
        return f"{int(secs // 3600)}h ago"
    return f"{int(secs // 86400)}d ago"


def _date(dt: datetime) -> str:
    """Absolute release date, e.g. '24 Sep 2026'."""
    return f"{dt.day} {dt:%b %Y}"


def _code_chip(it: Item) -> str:
    codes = [t for t in it.tags if _CODE.match(t)]
    return f'<span class="code">{_esc(" · ".join(codes[:2]))}</span>' if codes else ""


def _hero(it: Item) -> str:
    words = [t for t in it.tags if not _CODE.match(t)][:1]
    wpill = f'<span class="wpill">{_esc(words[0])}</span>' if words else ""
    return (
        f'<a class="hero" href="{_esc(it.link)}" target="_blank" rel="noopener" '
        f'data-cat="{getattr(it,"category","news")}" data-sev="{it.severity}" data-src="{_esc(it.source)}">'
        f'<div class="hpills"><span class="sev sev-{it.severity}">{_LABEL.get(it.severity,"INFO")}</span>{wpill}</div>'
        f'<div class="htitle">{_esc(it.title)}</div>'
        f'<div class="hsum">{_esc(it.summary[:180])}</div>'
        f'<div class="hmeta"><span>{_esc(it.source)}</span><i class="d"></i>'
        f'<span>{_date(it.published)}</span><i class="d"></i>'
        f'<span>{_ago(it.published)}</span>{_code_chip(it)}</div></a>'
    )


def _row(it: Item) -> str:
    return (
        f'<a class="row" href="{_esc(it.link)}" target="_blank" rel="noopener" '
        f'data-cat="{getattr(it,"category","news")}" data-sev="{it.severity}" data-src="{_esc(it.source)}">'
        f'<span class="rdot" style="background:{_DOT.get(it.severity, "#7c8699")}"></span>'
        f'<div><div class="rtitle">{_esc(it.title)}</div>'
        f'<div class="rmeta">{_esc(it.source)} &middot; {_date(it.published)} &middot; {_ago(it.published)}</div></div></a>'
    )


def _panel(period: str, items: list[Item], sections, section_limits, cap) -> str:
    active = " active" if period == "daily" else ""
    if not items:
        return (f'<section class="panel{active}" data-p="{period}">'
                f'<p class="empty">No notable items in this window. All quiet.</p></section>')

    lead = items[0]  # single most important item across all categories
    body = f'<div class="lead-label">&#9679; LEAD THREAT</div>{_hero(lead)}'

    # bucket the rest by display category (items are already score-sorted)
    buckets: dict[str, list[Item]] = {}
    for it in items:
        if it is lead:
            continue
        buckets.setdefault(getattr(it, "category", "news"), []).append(it)

    configured = set()
    for cat, label in sections:
        configured.add(cat)
        seq = _diversify(buckets.get(cat, []), section_limits.get(cat, 12), cap)
        if seq:
            body += f'<div class="sec-label">{label}</div>' + "".join(_row(i) for i in seq)

    # never silently drop an item whose category isn't in the configured sections
    leftover = [i for c, lst in buckets.items() if c not in configured for i in lst]
    if leftover:
        body += '<div class="sec-label">OTHER</div>' + "".join(_row(i) for i in leftover[:8])

    return f'<section class="panel{active}" data-p="{period}">{body}</section>'


def _dashboard(digests, sources, sections) -> str:
    """Compact coverage summary over the recent (weekly) window: category +
    severity chips, plus an expandable per-source activity list (all configured
    sources, so a feed sitting at 0 is visible = quiet or broken)."""
    from collections import Counter
    window = digests.get("weekly") or digests.get("monthly") or digests.get("daily") or []
    src_names = [s["name"] for s in sources] if sources else sorted({i.source for i in window})

    by_cat = Counter(getattr(i, "category", "news") for i in window)
    by_src = Counter(i.source for i in window)
    crit = sum(1 for i in window if i.severity == "critical")
    high = sum(1 for i in window if i.severity == "high")

    short = {"advisories": "advisories", "intel": "intel", "health": "healthcare", "news": "news"}
    ccls = {"advisories": "c-adv", "intel": "c-intel", "health": "c-health", "news": "c-news"}
    chips = [f'<span class="chip cl" data-clear="1"><b>{len(window)}</b> items</span>']
    for cat, _ in sections:
        chips.append(f'<span class="chip cl {ccls.get(cat,"")}" data-fc="{cat}"><b>{by_cat.get(cat,0)}</b> '
                     f'{short.get(cat, cat)}</span>')
    if crit:
        chips.append(f'<span class="chip cl c-crit" data-fs="critical"><b>{crit}</b> critical</span>')
    if high:
        chips.append(f'<span class="chip cl c-high" data-fs="high"><b>{high}</b> high</span>')

    counts = [(n, by_src.get(n, 0)) for n in src_names]
    counts.sort(key=lambda x: (-x[1], x[0].lower()))
    maxc = max((c for _, c in counts), default=0) or 1
    rows = ""
    for name, c in counts:
        pct = int(c / maxc * 100)
        q = " q" if c == 0 else ""
        rows += (f'<div class="srow{q}"><span class="sn">{_esc(name)}</span>'
                 f'<span class="sbar"><i style="width:{pct}%"></i></span>'
                 f'<span class="sc">{c}</span></div>')
    live = sum(1 for _, c in counts if c > 0)

    return (
        '<div class="dash"><div class="dash-h">COVERAGE &middot; LAST 7 DAYS '
        '&middot; <span class="hint">tap to filter</span></div>'
        f'<div class="chips">{"".join(chips)}</div>'
        f'<details class="srcs-t"><summary>Per-source activity &middot; {live}/{len(counts)} active</summary>'
        f'<div class="srcs">{rows}</div>'
        '<div class="dnote">Bars are item counts over the last 7 days. '
        '0 = quiet this week, or the feed needs attention.</div></details></div>'
    )


def _rail(digests, sources, iocs=None) -> str:
    """Desktop right rail, two stacked panels:
    TOP  — full CVE numbers published across the source feeds (click to open).
    BOTTOM — malware hash IOCs (source → threat → CVE) from ThreatFox + any
             hashes found in the feeds themselves."""
    import re as _re
    window = digests.get("weekly") or digests.get("monthly") or digests.get("daily") or []
    cve_re = _re.compile(r"CVE-\d{4}-\d{4,7}", _re.I)

    # ---- TOP: CVE numbers ----
    seen: set = set()
    cve_rows = []
    for it in window:  # score-ordered
        cves = [t.upper() for t in it.tags if cve_re.fullmatch(t or "")]
        if not cves:
            cves = [c.upper() for c in cve_re.findall(it.title + " " + it.summary)]
        for c in cves:
            if c in seen:
                continue
            seen.add(c)
            cve_rows.append((c, it.source, it.link))
    cve_html = "".join(
        f'<a class="rl" href="{_esc(link)}" target="_blank" rel="noopener">'
        f'<span class="cid">{_esc(cid)}</span><span class="rl-src">{_esc(src)}</span></a>'
        for cid, src, link in cve_rows[:80]
    ) or '<div class="rl-empty">No CVE numbers in this window.</div>'

    # ---- BOTTOM: hash IOCs ----
    hseen: set = set()
    hash_rows = []
    for io in (iocs or []):
        h = io.get("hash", "")
        if not h or h in hseen:
            continue
        hseen.add(h)
        hash_rows.append((h, io.get("htype", ""), io.get("malware", ""),
                          io.get("cve", ""), io.get("link", "#")))
    # supplement with hashes that appear directly in the feeds
    hex_re = _re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
    for it in window:
        for h in hex_re.findall(f"{it.title} {it.summary}"):
            if h in hseen:
                continue
            hseen.add(h)
            kind = {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(len(h), "")
            cve = (cve_re.search(it.title + " " + it.summary) or [None])
            cve = cve.group(0).upper() if hasattr(cve, "group") else ""
            hash_rows.append((h, kind, it.source, cve, it.link))

    def _hrow(h, kind, threat, cve, link):
        short = h if len(h) <= 22 else f"{h[:14]}\u2026{h[-6:]}"
        meta = " &middot; ".join(x for x in (threat, cve) if x)
        return (f'<a class="rl hrow" href="{_esc(link)}" target="_blank" rel="noopener" '
                f'title="{_esc(h)}"><span class="htag">{_esc(kind)}</span>'
                f'<span class="hval">{_esc(short)}</span>'
                + (f'<span class="hmeta2">{_esc(meta)}</span>' if meta else "")
                + '</a>')

    hash_html = "".join(_hrow(*r) for r in hash_rows[:80]) or (
        '<div class="rl-empty">No hash IOCs available. Enable network on the '
        'build runner so ThreatFox can be reached.</div>')

    body = (
        f'<div class="rail-sec"><div class="rail-h">CVE NUMBERS</div>'
        f'<div class="rail-list">{cve_html}</div></div>'
        f'<div class="rail-sec"><div class="rail-h">HASH IOCs &middot; source / threat / CVE</div>'
        f'<div class="rail-list">{hash_html}</div></div>'
    )
    # continuous scroll: duplicate the body so the loop is seamless; speed scales
    # with content length (slower when there's more to read).
    n = min(len(cve_rows), 80) + min(len(hash_rows), 80)
    dur = max(28, int(n * 1.6))
    return (
        '<aside class="rail"><div class="rail-scroll">'
        f'<div class="rail-track" style="animation-duration:{dur}s">{body}{body}</div>'
        '</div></aside>'
    )


def render_inner(digests: dict[str, list[Item]], display=None, sources=None, iocs=None) -> str:
    """The secret part: dashboard + tabs + panels. This is what gets encrypted."""
    sections, section_limits, cap = _resolve_display(display)
    dash = _dashboard(digests, sources, sections)
    tabs = "".join(
        f'<button class="tab{" active" if p == "daily" else ""}" data-t="{p}">{lbl}</button>'
        for p, lbl in _TABS
    )
    # source strip: All + EVERY configured source (mandatory), busiest first.
    # JS hides the ones with no items in the current tab + active filter.
    from collections import Counter
    widest = digests.get("monthly") or digests.get("weekly") or digests.get("daily") or []
    cnt = Counter(i.source for i in widest)
    names = [s["name"] for s in sources] if sources else list(cnt)
    names.sort(key=lambda n: (-cnt.get(n, 0), n.lower()))
    stabs = '<span class="stab on" data-fsrc="">All sources</span>' + "".join(
        f'<span class="stab" data-fsrc="{_esc(s)}">{_esc(s)}</span>' for s in names
    )
    strip = f'<div class="srcstrip-l">BROWSE BY SOURCE</div><div class="srcstrip">{stabs}</div>'
    panels = "".join(
        _panel(p, digests.get(p, []), sections, section_limits, cap) for p, _ in _TABS
    )
    side = f'<aside class="side">{dash}{strip}</aside>'
    main = f'<div class="main"><div class="tabs">{tabs}</div>{panels}</div>'
    rail = _rail(digests, sources, iocs)
    return f'<div class="layout">{side}{main}{rail}</div>'


_STYLE = """
:root{color-scheme:dark}*{box-sizing:border-box}
body{margin:0;background:#0a0e16;color:#f4f7fb;font:16px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:620px;margin:0 auto;padding:16px 14px 40px}
.layout{display:block}
.top{display:flex;align-items:center;justify-content:space-between;margin:4px 2px 18px}
.brand{display:flex;align-items:center;gap:8px}
.brand .mk{font-size:20px;color:#6ee7d6}
.brand .nm{font-size:18px;font-weight:500;letter-spacing:1.5px}
.pill{font-size:11px;color:#9aa6bd;background:#161d2b;border:1px solid #232c3d;padding:4px 9px;border-radius:999px;display:flex;align-items:center;gap:5px}
.pill .live{width:6px;height:6px;border-radius:50%;background:#6ee7d6}
.tag{font-size:12px;color:#7c8699;margin:-10px 2px 16px}
.tabs{display:flex;gap:5px;background:#131a27;border:1px solid #232c3d;padding:4px;border-radius:999px;margin-bottom:18px}
.tab{flex:1;padding:8px;font-size:13px;color:#9aa6bd;background:none;border:none;border-radius:999px;cursor:pointer}
.tab.active{background:#f4f7fb;color:#0a0e16;font-weight:500}
.panel{display:none}.panel.active{display:block}
.lead-label,.sec-label{display:flex;align-items:center;gap:8px;font-size:11px;font-weight:500;letter-spacing:1px;margin:0 2px 10px}
.lead-label{color:#ff8080}.sec-label{color:#7c8699;margin-top:20px}
.lead-label::after,.sec-label::after{content:"";flex:1;height:1px;background:#232c3d}
.hero{display:block;background:#161d2b;border:1px solid #2a3345;border-radius:18px;padding:16px;text-decoration:none;color:inherit}
.hpills{display:flex;gap:6px;margin-bottom:10px}
.sev{font-size:10.5px;font-weight:500;padding:3px 9px;border-radius:999px}
.sev-critical{color:#ff8080;background:#2a1618}.sev-high{color:#ffb020;background:#2a2110}
.sev-medium{color:#ffd84d;background:#2a2810}.sev-info{color:#9aa6bd;background:#1b2333}
.wpill{font-size:10.5px;color:#9aa6bd;background:#1b2333;padding:3px 9px;border-radius:999px}
.htitle{font-size:17px;font-weight:500;line-height:1.35;color:#f4f7fb;margin-bottom:7px}
.hsum{font-size:13px;line-height:1.5;color:#aab4c7;margin-bottom:12px}
.hmeta{display:flex;align-items:center;gap:8px;font-size:11.5px;color:#7c8699}
.hmeta .d{width:3px;height:3px;border-radius:50%;background:#4a5468}
.code{margin-left:auto;font-size:10.5px;color:#8ea0b8;background:#12202a;padding:3px 8px;border-radius:6px}
.row{display:flex;gap:11px;padding:12px 4px;border-bottom:1px solid #1a2230;text-decoration:none;color:inherit}
.rdot{width:8px;height:8px;border-radius:50%;margin-top:5px;flex-shrink:0}
.rtitle{font-size:14px;font-weight:500;line-height:1.35;color:#e6ecf5;margin-bottom:3px}
.rmeta{font-size:11.5px;color:#7c8699}
.empty{color:#7c8699;text-align:center;padding:36px 0}
.share{width:100%;background:#6ee7d6;color:#08201c;border:none;border-radius:12px;padding:13px;font-size:14px;font-weight:500;margin-top:20px;display:flex;align-items:center;justify-content:center;gap:7px;text-decoration:none}
.foot{text-align:center;font-size:11.5px;color:#5a6274;margin-top:14px}
.gate{max-width:320px;margin:50px auto;text-align:center}
.gate .lk{font-size:34px;color:#6ee7d6}
.gate p{color:#aab4c7;font-size:14px}
.gate input{width:100%;padding:12px;font-size:16px;border-radius:12px;border:1px solid #232c3d;background:#161d2b;color:#f4f7fb;margin:12px 0}
.gate button{width:100%;padding:12px;font-size:15px;font-weight:500;border:none;border-radius:12px;background:#6ee7d6;color:#08201c;cursor:pointer}
.err{color:#ff8080;font-size:13px;min-height:18px;margin-top:8px}
.dash{background:#131a27;border:1px solid #232c3d;border-radius:14px;padding:13px 13px 11px;margin-bottom:18px}
.dash-h{font-size:11px;font-weight:500;letter-spacing:1px;color:#7c8699;margin-bottom:10px}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{font-size:11.5px;color:#9aa6bd;background:#0f1622;border:1px solid #232c3d;padding:4px 9px;border-radius:999px}
.chip b{color:#f4f7fb;font-weight:600}
.chip.c-adv b{color:#ff8a8a}.chip.c-intel b{color:#6ee7d6}.chip.c-health b{color:#ffb020}.chip.c-news b{color:#cbd5e6}
.chip.c-crit{border-color:#3a1d20}.chip.c-crit b{color:#ff8080}.chip.c-high b{color:#ffb020}
.chip.cl{cursor:pointer;transition:background .15s,border-color .15s,color .15s}
.chip.cl:hover{border-color:#3a475d}
.chip.on{background:#f4f7fb;border-color:#f4f7fb;color:#0a0e16}
.chip.on b{color:#0a0e16}
.hint{color:#5a6274;font-weight:400;letter-spacing:0}
.srcstrip-l{font-size:11px;font-weight:500;letter-spacing:1px;color:#7c8699;margin:2px 0 7px}
.srcstrip{display:flex;flex-wrap:wrap;gap:6px;padding-bottom:11px;margin-bottom:6px}
.stab{flex:0 0 auto;cursor:pointer;font-size:10.5px;color:#9aa6bd;background:#0f1622;border:1px solid #232c3d;padding:3px 8px;border-radius:999px;white-space:nowrap;transition:background .15s,color .15s,border-color .15s}
.stab:hover{border-color:#3a475d}
.stab.on{background:#6ee7d6;border-color:#6ee7d6;color:#08110f;font-weight:600}
.disclaimer{margin-top:18px;padding:11px 13px;background:#0f1622;border:1px solid #232c3d;border-radius:12px;font-size:11px;line-height:1.55;color:#7c8699}
.disclaimer b{color:#9aa6bd}
/* right rail (desktop only) */
.rail{display:none}
.rail-sec{margin-bottom:22px}
.rail-h{font-size:11px;font-weight:500;letter-spacing:1px;color:#7c8699;margin-bottom:9px}
.rail-list{display:flex;flex-direction:column;gap:1px}
.rl{display:block;padding:6px 9px;border-radius:9px;text-decoration:none;font-size:12px;line-height:1.35;color:#c3ccdb;transition:background .12s}
.rl:hover{background:#131a27}
.cid{display:inline-block;font-weight:600;color:#6ee7d6;font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace;margin-right:8px}
.rl-src{color:#7c8699;font-size:11px}
.hrow{display:flex;flex-wrap:wrap;align-items:baseline;gap:6px}
.htag{font-size:9.5px;font-weight:600;letter-spacing:.5px;color:#08110f;background:#6ee7d6;border-radius:5px;padding:1px 5px}
.hval{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;color:#c3ccdb}
.hmeta2{flex-basis:100%;color:#7c8699;font-size:10.5px}
.rl-empty{font-size:11.5px;color:#5a6274;padding:6px 9px;line-height:1.5}
.rail-scroll{overflow:hidden;position:relative}
.rail-track{display:flex;flex-direction:column}
@keyframes railscroll{from{transform:translateY(0)}to{transform:translateY(-50%)}}
/* ---- Desktop / wide-browser layout ---- */
@media (min-width:920px){
  .wrap{max-width:1140px;padding:26px 26px 56px}
  .layout{display:grid;grid-template-columns:340px 1fr;gap:32px;align-items:start}
  .side{position:sticky;top:22px;max-height:calc(100vh - 44px);overflow-y:auto;scrollbar-width:thin}
  .side::-webkit-scrollbar{width:6px}.side::-webkit-scrollbar-thumb{background:#232c3d;border-radius:3px}
  .main{min-width:0}
  .dash{margin-bottom:14px}
  .tabs{position:sticky;top:0;z-index:2}
  .htitle{font-size:20px}.hsum{font-size:14px}
  .rtitle{font-size:15px}
  .hero{padding:20px}
  .top{margin-bottom:22px}
}
@media (min-width:1240px){
  .wrap{max-width:1460px}
  .layout{grid-template-columns:320px minmax(0,1fr) 300px}
  .rail{display:block;position:sticky;top:22px;height:calc(100vh - 44px);overflow:hidden}
  .rail-scroll{height:100%}
  .rail-track{animation-name:railscroll;animation-timing-function:linear;animation-iteration-count:infinite}
  .rail:hover .rail-track{animation-play-state:paused}
}
@media (min-width:1240px) and (prefers-reduced-motion:reduce){
  .rail{overflow-y:auto;scrollbar-width:thin}
  .rail-track{animation:none}
  .rail-track>.rail-sec:nth-child(n+3){display:none}
}
.srcs-t{margin-top:11px}
.srcs-t>summary{cursor:pointer;font-size:11.5px;color:#8ea0b8;list-style:none;padding:5px 0 2px;user-select:none}
.srcs-t>summary::-webkit-details-marker{display:none}
.srcs-t>summary::before{content:"\\25B8  ";color:#6ee7d6}
.srcs-t[open]>summary::before{content:"\\25BE  "}
.srcs{margin-top:8px}
.srow{display:flex;align-items:center;gap:9px;padding:3px 0}
.sn{flex:0 0 42%;font-size:11.5px;color:#c3ccdb;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sbar{flex:1;height:6px;background:#0f1622;border-radius:999px;overflow:hidden}
.sbar i{display:block;height:100%;background:linear-gradient(90deg,#3a8f82,#6ee7d6);border-radius:999px}
.sc{flex:0 0 24px;text-align:right;font-size:11.5px;color:#9aa6bd}
.srow.q{opacity:.45}.srow.q .sc{color:#ff9b9b}
.dnote{font-size:10.5px;color:#5a6274;margin-top:9px}
"""


def build_plain(digests, share_url: str, brand: dict, display=None, sources=None, iocs=None) -> str:
    return _shell(datetime.now(timezone.utc), render_inner(digests, display, sources, iocs), share_url, brand, None)


def build_encrypted(salt_b64, iv_b64, ct_b64, iters, share_url: str, brand: dict) -> str:
    enc = {"salt": salt_b64, "iv": iv_b64, "ct": ct_b64, "it": iters}
    return _shell(datetime.now(timezone.utc), "", share_url, brand, enc)


def _shell(now, inner, share_url, brand, encrypted) -> str:
    name = brand.get("name", "Cindera")
    tagline = brand.get("tagline", "Your group's threat brief")
    wa = ("https://api.whatsapp.com/send?text="
          + f"{name}%20%E2%80%94%20threat%20brief%3A%20{share_url}".replace(" ", "%20"))
    head = (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{_esc(name)}</title><style>{_STYLE}</style></head><body><div class="wrap">'
            f'<div class="top"><div class="brand">'
            f'<span class="mk">&#128737;</span><span class="nm">{_esc(name.upper())}</span></div>'
            f'<span class="pill"><span class="live"></span>Updated {now:%H:%M} UTC</span></div>'
            f'<div class="tag">{_esc(tagline)} &middot; {now:%a %d %b %Y} UTC</div>')
    foot = (f'<a class="share" href="{wa}">&#128172; Share to group</a>'
            f'<div class="disclaimer"><b>Disclaimer.</b> Cindera aggregates headlines from '
            f'third-party public feeds. Items are not individually verified or endorsed, and every '
            f'link opens an external site. Automated screening drops obviously malicious links '
            f'(non-HTTPS, IP hosts, look-alike domains, direct downloads, shorteners) but is not a '
            f'guarantee &mdash; always confirm an item&#39;s authenticity and legitimacy at the '
            f'original source before acting.</div>'
            f'<div class="foot">Members only &middot; every item links to its source. '
            f'Verify before acting.</div></div>')

    tab_js = ("function bindTabs(){document.querySelectorAll('.tab').forEach(function(t){"
              "t.onclick=function(){var p=t.dataset.t;"
              "document.querySelectorAll('.tab').forEach(function(x){x.classList.toggle('active',x===t)});"
              "document.querySelectorAll('.panel').forEach(function(s){s.classList.toggle('active',s.dataset.p===p)});"
              "if(window.cinUpdate)cinUpdate();"
              "};});}")

    filter_js = (
        "var CF={src:'',cat:'',sev:''};"
        # sources that have >=1 item in the ACTIVE panel matching the current cat/sev
        "function cinPresent(){var p=document.querySelector('.panel.active'),m={};"
        "if(p)p.querySelectorAll('[data-cat]').forEach(function(el){"
        "if((!CF.cat||el.getAttribute('data-cat')===CF.cat)&&(!CF.sev||el.getAttribute('data-sev')===CF.sev))"
        "m[el.getAttribute('data-src')]=1;});return m;}"
        "function cinUpdate(){var m=cinPresent();"
        "if(CF.src&&!m[CF.src])CF.src='';"                       # selected source not in this view → reset to All
        "document.querySelectorAll('.panel').forEach(function(p){"
        "p.querySelectorAll('[data-cat]').forEach(function(el){"
        "var ok=(!CF.src||el.getAttribute('data-src')===CF.src)"
        "&&(!CF.cat||el.getAttribute('data-cat')===CF.cat)"
        "&&(!CF.sev||el.getAttribute('data-sev')===CF.sev);"
        "el.style.display=ok?'':'none';});"
        "p.querySelectorAll('.lead-label').forEach(function(l){var h=l.nextElementSibling;"
        "l.style.display=(h&&h.style.display==='none')?'none':'';});"
        "p.querySelectorAll('.sec-label').forEach(function(lbl){var vis=false,n=lbl.nextElementSibling;"
        "while(n&&!n.classList.contains('sec-label')){"
        "if(n.hasAttribute('data-cat')&&n.style.display!=='none'){vis=true;break;}n=n.nextElementSibling;}"
        "lbl.style.display=vis?'':'none';});});"
        # hide source chips with no items in the current view
        "document.querySelectorAll('.stab').forEach(function(c){var s=c.getAttribute('data-fsrc');"
        "c.style.display=(s===''||m[s])?'':'none';});"
        "cinPaint();}"
        "function cinPaint(){"
        "document.querySelectorAll('.chip.cl[data-fc]').forEach(function(c){c.classList.toggle('on',CF.cat!==''&&c.getAttribute('data-fc')===CF.cat)});"
        "document.querySelectorAll('.chip.cl[data-fs]').forEach(function(c){c.classList.toggle('on',CF.sev!==''&&c.getAttribute('data-fs')===CF.sev)});"
        "document.querySelectorAll('.stab').forEach(function(c){c.classList.toggle('on',c.getAttribute('data-fsrc')===CF.src)});}"
        "function cinWeekly(){document.querySelectorAll('.tab').forEach(function(x){x.classList.toggle('active',x.dataset.t==='weekly')});"
        "document.querySelectorAll('.panel').forEach(function(s){s.classList.toggle('active',s.dataset.p==='weekly')});}"
        "function bindFilter(){"
        "document.querySelectorAll('.chip.cl').forEach(function(c){c.onclick=function(){"
        "if(c.hasAttribute('data-clear')){CF.cat='';CF.sev='';}"
        "else if(c.hasAttribute('data-fc')){var v=c.getAttribute('data-fc');CF.cat=(CF.cat===v?'':v);if(CF.cat)cinWeekly();}"
        "else if(c.hasAttribute('data-fs')){var v=c.getAttribute('data-fs');CF.sev=(CF.sev===v?'':v);if(CF.sev)cinWeekly();}"
        "cinUpdate();};});"
        "document.querySelectorAll('.stab').forEach(function(c){c.onclick=function(){"
        "if(c.style.display==='none')return;"
        "var v=c.getAttribute('data-fsrc');CF.src=(CF.src===v?'':v);cinUpdate();};});"
        "cinUpdate();}"                                          # initial pass: hide empty sources for Daily
    )

    if encrypted is None:
        return head + f'<div id="app">{inner}</div>' + foot + f'<script>{tab_js}{filter_js}bindTabs();bindFilter();</script></body></html>'

    gate = ('<div id="gate" class="gate"><div class="lk">&#128274;</div>'
            '<p>Members only. Enter the group passphrase.</p>'
            '<input id="pw" type="password" placeholder="Passphrase" autocomplete="off">'
            '<button id="go">Unlock</button><div id="err" class="err"></div></div>'
            '<div id="app" style="display:none"></div>')
    dec_js = (
        "var ENC=" + json.dumps(encrypted) + ";"
        "var dec=new TextDecoder(),enc=new TextEncoder();"
        "function b64(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0)});}"
        "async function unlock(p){var s=b64(ENC.salt),iv=b64(ENC.iv),ct=b64(ENC.ct);"
        "var bk=await crypto.subtle.importKey('raw',enc.encode(p),{name:'PBKDF2'},false,['deriveKey']);"
        "var k=await crypto.subtle.deriveKey({name:'PBKDF2',salt:s,iterations:ENC.it,hash:'SHA-256'},"
        "bk,{name:'AES-GCM',length:256},false,['decrypt']);"
        "return dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:iv},k,ct));}"
        "async function attempt(p){try{document.getElementById('app').innerHTML=await unlock(p);"
        "document.getElementById('gate').style.display='none';"
        "document.getElementById('app').style.display='block';bindTabs();bindFilter();return true;}catch(e){return false;}}"
        "document.getElementById('go').onclick=async function(){var p=document.getElementById('pw').value;"
        "if(!p){document.getElementById('err').textContent='Enter the passphrase';return;}"
        "document.getElementById('err').textContent='Checking…';"
        "if(!await attempt(p))document.getElementById('err').textContent='Wrong passphrase';};"
        "document.getElementById('pw').addEventListener('keydown',function(e){"
        "if(e.key==='Enter')document.getElementById('go').click();});"
        "(function(){var m=location.hash.match(/k=([^&]+)/);if(m)attempt(decodeURIComponent(m[1]));})();"
    )
    return head + gate + foot + f'<script>{tab_js}{filter_js}{dec_js}</script></body></html>'
