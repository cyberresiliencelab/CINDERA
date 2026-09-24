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


def render_inner(digests: dict[str, list[Item]], display=None, sources=None) -> str:
    """The secret part: dashboard + tabs + panels. This is what gets encrypted."""
    sections, section_limits, cap = _resolve_display(display)
    dash = _dashboard(digests, sources, sections)
    tabs = "".join(
        f'<button class="tab{" active" if p == "daily" else ""}" data-t="{p}">{lbl}</button>'
        for p, lbl in _TABS
    )
    # source strip: All + each source that has items, busiest first
    from collections import Counter
    widest = digests.get("monthly") or digests.get("weekly") or digests.get("daily") or []
    order = [s for s, _ in Counter(i.source for i in widest).most_common()]
    stabs = '<span class="stab on" data-fsrc="">All sources</span>' + "".join(
        f'<span class="stab" data-fsrc="{_esc(s)}">{_esc(s)}</span>' for s in order
    )
    strip = f'<div class="srcstrip-l">BROWSE BY SOURCE</div><div class="srcstrip">{stabs}</div>'
    panels = "".join(
        _panel(p, digests.get(p, []), sections, section_limits, cap) for p, _ in _TABS
    )
    return f'{dash}<div class="tabs">{tabs}</div>{strip}{panels}'


_STYLE = """
:root{color-scheme:dark}*{box-sizing:border-box}
body{margin:0;background:#0a0e16;color:#f4f7fb;font:16px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:560px;margin:0 auto;padding:16px 14px 40px}
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


def build_plain(digests, share_url: str, brand: dict, display=None, sources=None) -> str:
    return _shell(datetime.now(timezone.utc), render_inner(digests, display, sources), share_url, brand, None)


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
            f'<div class="foot">Members only &middot; every item links to its source. '
            f'Verify before acting.</div></div>')

    tab_js = ("function bindTabs(){document.querySelectorAll('.tab').forEach(function(t){"
              "t.onclick=function(){var p=t.dataset.t;"
              "document.querySelectorAll('.tab').forEach(function(x){x.classList.toggle('active',x===t)});"
              "document.querySelectorAll('.panel').forEach(function(s){s.classList.toggle('active',s.dataset.p===p)});"
              "};});}")

    filter_js = (
        "var CF={src:'',cat:'',sev:''};"
        "function cinApply(){document.querySelectorAll('.panel').forEach(function(p){"
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
        "lbl.style.display=vis?'':'none';});});}"
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
        "cinPaint();cinApply();};});"
        "document.querySelectorAll('.stab').forEach(function(c){c.onclick=function(){"
        "var v=c.getAttribute('data-fsrc');CF.src=(CF.src===v?'':v);cinPaint();cinApply();};});}"
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
