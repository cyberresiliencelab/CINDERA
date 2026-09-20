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
_DEFAULT_SECTION_LIMITS = {"advisories": 12, "intel": 10, "health": 8, "news": 10}


def _resolve_display(display):
    display = display or {}
    secs = display.get("sections")
    if secs:
        sections = [(s["category"], s.get("label", s["category"].upper())) for s in secs]
    else:
        sections = list(_DEFAULT_SECTIONS)
    limits = dict(_DEFAULT_SECTION_LIMITS)
    limits.update(display.get("section_limits", {}) or {})
    return sections, limits
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


def _code_chip(it: Item) -> str:
    codes = [t for t in it.tags if _CODE.match(t)]
    return f'<span class="code">{_esc(" · ".join(codes[:2]))}</span>' if codes else ""


def _hero(it: Item) -> str:
    words = [t for t in it.tags if not _CODE.match(t)][:1]
    wpill = f'<span class="wpill">{_esc(words[0])}</span>' if words else ""
    return (
        f'<a class="hero" href="{_esc(it.link)}" target="_blank" rel="noopener">'
        f'<div class="hpills"><span class="sev sev-{it.severity}">{_LABEL.get(it.severity,"INFO")}</span>{wpill}</div>'
        f'<div class="htitle">{_esc(it.title)}</div>'
        f'<div class="hsum">{_esc(it.summary[:180])}</div>'
        f'<div class="hmeta"><span>{_esc(it.source)}</span><i class="d"></i>'
        f'<span>{_ago(it.published)}</span>{_code_chip(it)}</div></a>'
    )


def _row(it: Item) -> str:
    return (
        f'<a class="row" href="{_esc(it.link)}" target="_blank" rel="noopener">'
        f'<span class="rdot" style="background:{_DOT.get(it.severity, "#7c8699")}"></span>'
        f'<div><div class="rtitle">{_esc(it.title)}</div>'
        f'<div class="rmeta">{_esc(it.source)} &middot; {_ago(it.published)}</div></div></a>'
    )


def _panel(period: str, items: list[Item], sections, section_limits) -> str:
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
        seq = buckets.get(cat, [])[: section_limits.get(cat, 8)]
        if seq:
            body += f'<div class="sec-label">{label}</div>' + "".join(_row(i) for i in seq)

    # never silently drop an item whose category isn't in the configured sections
    leftover = [i for c, lst in buckets.items() if c not in configured for i in lst]
    if leftover:
        body += '<div class="sec-label">OTHER</div>' + "".join(_row(i) for i in leftover[:8])

    return f'<section class="panel{active}" data-p="{period}">{body}</section>'


def render_inner(digests: dict[str, list[Item]], display=None) -> str:
    """The secret part: tabs + panels. This is what gets encrypted."""
    sections, section_limits = _resolve_display(display)
    tabs = "".join(
        f'<button class="tab{" active" if p == "daily" else ""}" data-t="{p}">{lbl}</button>'
        for p, lbl in _TABS
    )
    panels = "".join(
        _panel(p, digests.get(p, []), sections, section_limits) for p, _ in _TABS
    )
    return f'<div class="tabs">{tabs}</div>{panels}'


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
"""


def build_plain(digests, share_url: str, brand: dict, display=None) -> str:
    return _shell(datetime.now(timezone.utc), render_inner(digests, display), share_url, brand, None)


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

    if encrypted is None:
        return head + f'<div id="app">{inner}</div>' + foot + f'<script>{tab_js}bindTabs();</script></body></html>'

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
        "document.getElementById('app').style.display='block';bindTabs();return true;}catch(e){return false;}}"
        "document.getElementById('go').onclick=async function(){var p=document.getElementById('pw').value;"
        "if(!p){document.getElementById('err').textContent='Enter the passphrase';return;}"
        "document.getElementById('err').textContent='Checking…';"
        "if(!await attempt(p))document.getElementById('err').textContent='Wrong passphrase';};"
        "document.getElementById('pw').addEventListener('keydown',function(e){"
        "if(e.key==='Enter')document.getElementById('go').click();});"
        "(function(){var m=location.hash.match(/k=([^&]+)/);if(m)attempt(decodeURIComponent(m[1]));})();"
    )
    return head + gate + foot + f'<script>{tab_js}{dec_js}</script></body></html>'
