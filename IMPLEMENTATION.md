# Cindera — Option 1: pinned encrypted link (free, ToS-compliant)

One link you pin in your WhatsApp group. It's an **encrypted** page that rebuilds
itself daily on GitHub Pages, so the single pinned link is always current. Only
people with the passphrase can read it. Sharing a URL breaks no WhatsApp rules,
and there's no cost.

## How the privacy works
- The digest is encrypted at build time with **AES-256-GCM**; the key is derived
  from your passphrase via **PBKDF2-HMAC-SHA256 (250k iterations)**.
- The published `index.html` is **ciphertext only** — a stranger with the URL sees
  a lock screen, no headlines, no links.
- Decryption happens in the reader's browser after they enter the passphrase. The
  passphrase is never in the file and never reaches GitHub.

Because the file holds no secrets, a **public repo is fine** (and keeps it free on
GitHub's plan). The passphrase lives only as a GitHub Actions secret.

## Setup (about 10 minutes)

1. **Create a GitHub repo** and push these files (public repo is fine).

2. **Add the passphrase secret:** repo → Settings → Secrets and variables →
   Actions → New repository secret → name `PAGE_PASSPHRASE`, value = your chosen
   group passphrase (use 4+ random words).

3. **Turn on Pages:** repo → Settings → Pages → Source = **GitHub Actions**.

4. **Publish:** push to `main`, or Actions → "Build & Publish Cindera" → Run
   workflow. After ~1 minute your link is
   `https://<you>.github.io/<repo>/`.

5. **Pin it in the group** and share the passphrase in a **separate** message.
   Each member enters it once (their browser remembers it per device).

The workflow rebuilds twice a day at 06:00 and 18:00 UTC (refreshing the weekly/monthly
tabs in the same run). Hit "Run workflow" any time for an instant refresh.

## Two ways members unlock
- **Type it (most private):** open link → enter passphrase.
- **One tap (less private):** append `#k=your-passphrase` to the link. The `#`
  part stays in the browser and never reaches GitHub, but anyone the link is
  forwarded to also gets in. Use only if convenience beats strict control.

## Rotating the passphrase
Someone left the group, or it leaked? Change the `PAGE_PASSPHRASE` secret and
re-run the workflow. The next build re-encrypts with the new key; the old
passphrase (and any `#k=` links) stop working.

## Customising
- Sources / keywords / brand: `feeds.yaml`
- Page look, hero vs. list styling: `cyberdigest/site.py`
- Schedule: the `cron` line in `.github/workflows/pages.yml`

### Sources, tiers and categories
Each source in `feeds.yaml` takes two independent labels:
- **`tier`** (`news` | `advisory` | `intel`) affects **scoring** — `advisory` items
  get an actionability bonus so they rank higher.
- **`category`** (`advisories` | `intel` | `health` | `news`) affects **display** —
  which section the item appears under. If omitted, it falls back to `tier`.

Keeping them separate means a source can score like news but display in a specific
section (e.g. the healthcare feeds are `tier: news`, `category: health`).

### Browse-by-source strip & release dates
Below the time tabs is a horizontally scrollable source strip (All sources + one
chip per active source). Selecting a source filters the whole page to that source's
articles, still grouped under the four category headers. The source, coverage
category chips, and severity chips combine as one filter (e.g. CrowdStrike + critical).
Every article shows its absolute release date alongside the relative age.

### Available-source filtering
The source strip lists every configured feed, but shows only the ones that have
items for the current tab (Daily/Weekly/Monthly) AND any active category/severity
filter; the rest are hidden. Selecting a source that has nothing in the current
view resets to All. Availability is computed live from the DOM in `cinUpdate()`.

### Malicious-link screening (every build)
`fetch._safe_link` drops items whose link is non-HTTPS, points to a raw-IP host or
punycode/look-alike domain, carries credentials, is a direct executable download,
or uses a URL shortener. It is heuristic, not a reputation service — for real domain
reputation add a Google Safe Browsing lookup keyed by a repo secret. Fetch now also
uses a browser User-Agent with retries and an optional per-source `fallback_url`.

### Desktop right rail (continuous ticker)
At >=1240px a third column appears: a scrolling quick-access rail with full CVE numbers
published across the feeds (click to open) on top, and malware hash IOCs
(source -> threat -> CVE, via abuse.ch ThreatFox + hashes found in feeds) below. Built server-side in `_rail()` from the weekly window; hidden below 1240px. The rail auto-scrolls as a seamless vertical ticker (content duplicated, CSS keyframes, speed scales with length); it pauses on hover so links stay clickable, and falls back to manual scrolling under prefers-reduced-motion. Layout is now 1-col (mobile) / 2-col (>=920px) / 3-col (>=1240px).

### Responsive layout (mobile vs desktop)
One page, two layouts via CSS. On phones/tablets it's a single column: summary,
source strip, time tabs, then articles. At >=920px the `.layout` grid splits into a
sticky left sidebar (coverage summary + source strip) and a wide main pane (tabs +
articles), using the browser width instead of wasting it; the sidebar stays in view
while the article list scrolls. All filtering/tab JS uses global selectors, so it
works identically in both layouts. Note: the local wkhtmltoimage renderer can't show
CSS grid (ancient WebKit) — verify the desktop layout in a real browser or devtools.

### Coverage dashboard
The encrypted page opens with a compact **coverage panel** over the last 7 days:
category totals (advisories / intel / healthcare / news), a critical/high count,
and an expandable per-source activity list covering all configured sources. A
source showing 0 is either quiet that week or its feed has broken — so the panel
doubles as a lightweight feed-health check. Rendered server-side in `site.py`
(`_dashboard`); no external JS/chart library.

### Sections shown under each tab
The `display:` block controls the on-page grouping:
```yaml
display:
  sections:                       # order = order on the page
    - {category: advisories, label: "CVE &amp; ADVISORIES"}
    - {category: intel,      label: "THREAT ACTOR / INTEL"}
    - {category: health,     label: "HEALTHCARE BREACHES"}
    - {category: news,       label: "OTHER NEWS"}
  section_limits: {advisories: 12, intel: 10, health: 8, news: 10}
```
Each section takes its own top-N by score, so a busy advisories day can't bury the
news or healthcare items. Add/reorder sections or change limits here — any item whose
category isn't listed still appears under an automatic "OTHER" section, never dropped.

### Tap-to-filter coverage chips
Every chip in the coverage panel is a filter. Tapping a category (advisories /
intel / healthcare / news) or a severity (critical / high) switches to the 7-day
Weekly view and lists just those items; tapping the highlighted chip again, or the
"items" chip, clears it. Pure client-side JS (`cinF`/`bindFilter` in `site.py`),
bound after decrypt so it works on the encrypted page too.

### Source diversity (no single source dominates)
Within each section, sources are interleaved round-robin — the best item from
each source, then the second from each, and so on — bounded by `per_source_cap`
(max items from one source per section) and the section limit. This stops a busy
source like CrowdStrike from filling a whole section, and gives every source of
the 25 real estate. Raise `per_source_cap`/`section_limits` in feeds.yaml for more
per source; lower them for a tighter brief.

### Healthcare routing
Only HIPAA Journal is tagged `health` directly (it is healthcare-only). In
addition, an item from *any* source whose title/summary matches `health_keywords`
in `feeds.yaml` is routed into the Healthcare section — so a hospital breach reported
by a general-news outlet still lands there. Matching is word-boundary based (so
"phishing" won't trigger "phi"), and formal advisories are left under Advisories.
If legitimate health items land in News, widen `health_keywords`.

### A note on datacenter fetching
The build runs on GitHub's runners (a datacenter IP). A few publishers return **403**
to datacenter requests while serving browsers fine. Cindera skips dead feeds, so such
a source simply shows `0 in window` / `fetch failed` in the Actions log rather than
breaking the run. Swap in an alternate feed URL if one is persistently blocked.

## Run locally (optional preview)
```bash
pip install -r requirements.txt
PAGE_PASSPHRASE="reef tiger otter" python -m cyberdigest.build --out public
# open public/index.html, enter the passphrase
```

## Honest limits
- The published page is public but encrypted; privacy is the passphrase, not the host.
- It's a *shared* passphrase — a member can forward it (or a `#k=` link). Rotate if
  that happens.
- Pick a strong passphrase; weak ones are brute-forceable offline against the ciphertext.
- Summaries come from feed text — every item links to its source; verify before acting.

### Desktop redesign notes
- Column 1 holds only the coverage dashboard; its chips + per-source activity graph
  are timeline-aware (three `.dashwin` blocks toggled with the Daily/Weekly/Monthly tab).
- The Browse-by-source ribbon now lives in column 2, below the tabs and above the lead.
- Right-rail CVE panel is grouped released-month -> source -> CVE numbers; hashes below.
- `rescan_hashes()` fetches article pages for feeds that don't publish hashes in RSS
  (bounded by `hash_rescan` in feeds.yaml, default 12).
- Login gate is a centered card; the Share button is a compact pill.

### Mobile ticker ribbons
On mobile/tablet (where the right rail is hidden) two horizontal auto-scroll ribbons
bracket the disclaimer: CVE numbers above, hash IOCs below (`_mobile_ribbons`). They
loop left->right (duplicated track, CSS keyframes), pause on tap/hover, and fall back
to manual horizontal scroll under prefers-reduced-motion. Hidden at >=1240px. The
disclaimer now lives inside the encrypted content (so the ribbons can bracket it and
nothing leaks on the locked page); the footer keeps only the share + members-only line.
