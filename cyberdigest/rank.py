"""Score and prioritise items so the digest leads with what matters."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .fetch import Item

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_CVSS = re.compile(r"cvss[:\s]*v?\d?\.?\d?[:\s]*([0-9]{1,2}(?:\.\d)?)", re.I)

_SEV_ORDER = {"critical": 3, "high": 2, "medium": 1, "info": 0}
_SEV_RANK = {v: k for k, v in _SEV_ORDER.items()}


def _extract_cvss(text: str) -> float:
    best = 0.0
    for m in _CVSS.finditer(text):
        try:
            best = max(best, float(m.group(1)))
        except ValueError:
            continue
    return best


def score_item(it: Item, cfg: dict) -> Item:
    text = f"{it.title} {it.summary}".lower()
    keyword_cfg = cfg["keywords"]
    weights = cfg["priority_keywords"]

    sev = "info"
    score = it.weight  # start from source authority

    # keyword-driven severity (highest tier wins)
    for level in ("critical", "high", "medium"):
        hits = [kw for kw in keyword_cfg[level] if kw in text]
        if hits:
            score += weights[level] * len(hits)
            if _SEV_ORDER[level] > _SEV_ORDER[sev]:
                sev = level
            it.tags.extend(hits[:2])

    # CVSS override
    cvss = _extract_cvss(text)
    if cvss >= cfg.get("cvss_critical_threshold", 9.0):
        sev = "critical"
        score += 3.0
        it.tags.append(f"CVSS {cvss}")

    # CVE presence is a concreteness signal
    cves = _CVE.findall(it.title + " " + it.summary)
    if cves:
        score += 0.5
        it.tags.extend(sorted(set(c.upper() for c in cves))[:3])

    # advisories are inherently actionable
    if it.tier == "advisory":
        score += 1.0

    # recency: gentle decay so a 6-day-old item ranks below a fresh one
    age_h = (datetime.now(timezone.utc) - it.published).total_seconds() / 3600
    score *= max(0.5, 1.0 - age_h / 720)  # ~30-day half-ish decay floor

    it.score = round(score, 3)
    it.severity = sev
    it.tags = list(dict.fromkeys(it.tags))  # unique, order-preserving
    return it


def rank(items: list[Item], cfg: dict, top_n: int | None = None) -> list[Item]:
    scored = [score_item(it, cfg) for it in items]
    scored.sort(key=lambda x: (x.score, x.published), reverse=True)
    return scored[:top_n] if top_n else scored


def severity_emoji(sev: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "info": "⚪"}.get(sev, "⚪")
