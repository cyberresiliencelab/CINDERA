"""Fetch and normalise items from all configured RSS/Atom feeds."""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import json as _json
from urllib.request import Request, urlopen

import feedparser

# Be a polite bot; some feeds reject the default UA.
_UA = "CyberDigestBot/1.0 (+https://github.com/your-org/cyber-digest)"


@dataclass
class Item:
    title: str
    link: str
    summary: str
    source: str
    tier: str
    weight: float
    published: datetime
    score: float = 0.0
    severity: str = "info"
    category: str = "news"  # display bucket: advisories | intel | health | news
    tags: list[str] = field(default_factory=list)

    @property
    def domain(self) -> str:
        return urlparse(self.link).netloc.replace("www.", "")

    def key(self) -> str:
        """Dedup key: normalised title is the strongest signal across sources."""
        norm = re.sub(r"[^a-z0-9 ]", "", self.title.lower()).strip()
        norm = re.sub(r"\s+", " ", norm)
        return hashlib.sha1(norm.encode()).hexdigest()


_HTML = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def _clean(text: str, limit: int = 600) -> str:
    text = _HTML.sub(" ", text or "")
    text = _WS.sub(" ", text).strip()
    return text[:limit].rsplit(" ", 1)[0] + "…" if len(text) > limit else text


def _parse_date(entry) -> datetime:
    for attr in ("published_parsed", "updated_parsed"):
        val = getattr(entry, attr, None)
        if val:
            return datetime.fromtimestamp(time.mktime(val), tz=timezone.utc)
    return datetime.now(timezone.utc)  # undated → treat as now, ranking handles it


def fetch_source(src: dict, since: datetime) -> list[Item]:
    """Fetch one source. Never raises — a dead feed must not kill the run."""
    items: list[Item] = []
    try:
        parsed = feedparser.parse(src["url"], agent=_UA)
    except Exception as exc:  # noqa: BLE001 - resilience over precision
        print(f"  ! {src['name']}: fetch failed ({exc})")
        return items

    if getattr(parsed, "bozo", 0) and not parsed.entries:
        print(f"  ! {src['name']}: unreadable feed, skipping")
        return items

    for e in parsed.entries:
        pub = _parse_date(e)
        if pub < since:
            continue
        title = _WS.sub(" ", (e.get("title") or "").strip())
        link = e.get("link") or ""
        if not title or not link:
            continue
        items.append(
            Item(
                title=title,
                link=link,
                summary=_clean(e.get("summary", "") or e.get("description", "")),
                source=src["name"],
                tier=src.get("tier", "news"),
                weight=float(src.get("weight", 1.0)),
                published=pub,
                category=src.get("category", src.get("tier", "news")),
            )
        )
    print(f"  · {src['name']}: {len(items)} in window")
    return items


def fetch_cisa_kev(src: dict, since: datetime) -> list[Item]:
    """CISA Known Exploited Vulnerabilities — JSON only since RSS was retired.
    Every entry is, by definition, actively exploited → forced high priority."""
    items: list[Item] = []
    try:
        req = Request(src["url"], headers={"User-Agent": _UA})
        with urlopen(req, timeout=30) as r:
            data = _json.loads(r.read().decode())
    except Exception as exc:  # noqa: BLE001
        print(f"  ! {src['name']}: fetch failed ({exc})")
        return items

    for v in data.get("vulnerabilities", []):
        try:
            pub = datetime.fromisoformat(v["dateAdded"]).replace(tzinfo=timezone.utc)
        except Exception:  # noqa: BLE001
            pub = datetime.now(timezone.utc)
        if pub < since:
            continue
        cve = v.get("cveID", "")
        name = v.get("vulnerabilityName", "").strip()
        vendor = " ".join(x for x in (v.get("vendorProject", ""), v.get("product", "")) if x)
        title = f"{cve}: {name}" if name else f"{cve}: {vendor}".strip(": ")
        summary = _clean(f"{v.get('shortDescription', '')} "
                         f"Required action: {v.get('requiredAction', '')}")
        it = Item(
            title=title or cve,
            link=f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else src["url"],
            summary=summary,
            source=src["name"],
            tier="advisory",
            weight=float(src.get("weight", 2.0)),
            published=pub,
            category=src.get("category", "advisories"),
        )
        it.tags = [cve] if cve else []
        if v.get("knownRansomwareCampaignUse", "").lower() == "known":
            it.tags.append("ransomware")
        it.tags.append("actively exploited")  # rank.py escalates this to critical
        items.append(it)
    print(f"  · {src['name']}: {len(items)} in window")
    return items


def dedupe(items: list[Item]) -> list[Item]:
    """Collapse the same story reported by multiple outlets, keeping the
    highest-weight source and remembering the others for cross-referencing."""
    best: dict[str, Item] = {}
    for it in items:
        k = it.key()
        if k not in best or it.weight > best[k].weight:
            # preserve any already-collected corroborating sources
            if k in best:
                it.tags = list(set(it.tags) | set(best[k].tags))
            best[k] = it
    return list(best.values())


def window_start(period: str, now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    return {
        "daily": now - timedelta(days=1),
        "weekly": now - timedelta(days=7),
        "monthly": now - timedelta(days=31),
        "interim": now - timedelta(hours=6),  # rapid check for breaking items
    }.get(period, now - timedelta(days=1))


def collect(sources: list[dict], period: str) -> list[Item]:
    since = window_start(period)
    print(f"Fetching {len(sources)} sources since {since:%Y-%m-%d %H:%M UTC} ({period})")
    raw: list[Item] = []
    for src in sources:
        if src.get("format") in ("json_kev", "cisa_kev"):
            raw.extend(fetch_cisa_kev(src, since))
        else:
            raw.extend(fetch_source(src, since))
    deduped = dedupe(raw)
    print(f"Collected {len(raw)} items → {len(deduped)} after dedupe")
    return deduped
