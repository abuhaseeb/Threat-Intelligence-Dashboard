# Signal Desk — Cyber Threat Intel Dashboard

A local Flask UI over the 15 scrapers you provided. It has three tabs:

- **Social media** — X, Reddit, Instagram, Mastodon
- **Research blogs** — Sophos, Recorded Future, Intezer, CrowdStrike,
  Cisco Talos, Check Point Research, Malwarebytes, Palo Alto Unit 42
- **Trending Malware** — ANY.RUN, Malpedia, and ThreatFox, each shown as
  a data table (not the card list the other two tabs use) with every
  field that source provides and a link on each row to its page on the
  source site — see below

Each platform gets its own panel with:
- the default account/subreddit/instance pre-filled, editable before you run it
  (blogs have no search field — they always pull the latest posts from that
  vendor's blog listing)
- an `auth_token` field for X only (required there, used for that request
  only, never written to disk or logged)
- a result count field where the scraper supports one
- a **Run scrape** button that blocks until the browser session the scraper
  drives finishes and closes, then shows results — one run per click, no
  background polling
- per-item author/account, title or body, a description (summarized with
  newspaper3k for blog articles), and a **complete** IOC list grouped by
  type (IPs, domains, URLs, emails, MD5/SHA1/SHA256/SHA512, CVEs, MITRE
  ATT&CK IDs, file/registry paths) with every value shown and click-to-copy
  — see "IOC completeness" below
- **Export JSON** / **Export CSV** buttons for that platform's latest run,
  both carrying the full IOC detail, not just a count

## How it's wired

`scrapers/` holds the files you uploaded, unmodified apart from:
- `mastadon_scrapper.py` renamed to `mastodon_scraper.py` (typo fix, no
  logic changes)
- the hardcoded X `AUTH_TOKEN` value in `x_scraper.py` cleared to `""` —
  the dashboard supplies it per-request from what you type into the UI
  instead

Trellix is not included (removed on request).

`config.py` is a registry mapping each platform to its module, entrypoint
function, and which module-level constant to overwrite for account/limit/
auth token (e.g. `x` → `TARGET_USERNAME`, `reddit` → `SUBREDDIT_URL`).
`scraper_runner.py` re-imports the module fresh on every request, sets
those constants, redirects `OUTPUT_FILE` into this project's `output/`
folder, runs the scraper's own `main()` (or `scrape_talos()` for Cisco
Talos, or `scrape_mastodon_profile()` directly for Mastodon, since that
one already takes account/instance/limit as arguments), and reads back
the JSON it wrote. None of the scraping logic itself was rewritten.

`normalizer.py` turns whatever shape each scraper wrote (`posts` /
`reports` / `blogs` / `articles`, including formats that nest fields
under a sub-object — Intezer's `blog`/`source`/`content`, Unit 42's
`metadata`/`source`/`content`/`threat_intelligence`) into a common row
shape for the table view and CSV export, and — for blog articles —
replaces the description with a `newspaper3k` summary of the article
URL when that succeeds, falling back to the scraper's own extracted
description/snippet otherwise (paywalled or JS-only pages, no network,
etc. all degrade gracefully instead of failing the request).

### IOC completeness

The 12 original scrapers don't agree on IOC category names
(`ip_addresses` vs `ipv4_addresses` vs `ipv4`), some lump every hash
length into one `hashes` bucket, and Recorded Future's scraper doesn't
extract IOCs at all — so showing each scraper's raw `iocs` field as-is
gave an incomplete, inconsistent picture depending on the platform.

`ioc_extract.py` fixes that in two steps, run for every item on every
platform:
1. **Canonicalize** whatever IOC dict the scraper already produced into
   one fixed schema (`ipv4`, `ipv6`, `domains`, `urls`, `emails`, `md5`,
   `sha1`, `sha256`, `sha512`, `cves`, `mitre_attack`, `file_names`,
   `registry_paths`, `windows_paths`, `unix_paths`, `bitcoin_addresses`),
   classifying ambiguous same-bucket hash lists by string length.
2. **Re-extract** with a comprehensive, defang-aware regex sweep
   (`hxxp`, `[.]`, `[at]`, etc. all normalized first) over the item's
   own title/body/description text, and union that with step 1.

The result is deduplicated, sorted, and stored on every row — so an
item that came from a scraper with thin IOC extraction (or none) still
shows its full, correct IOC set in the UI, the CSV export
(`iocs_csv` column), and the JSON export (`iocs` + `ioc_count` layered
onto the original record).

### Trending Malware

ANY.RUN, Malpedia, and ThreatFox aren't posts or articles — each returns
a flat, already-ranked (top-20) list of records (ANY.RUN wraps its list
in `{"source": ..., "records": [...]}`; `normalizer.find_record_list()`
unwraps either shape), so this tab skips the post/IOC pipeline above
entirely and renders/exports each source as a plain table instead of
cards. The three scrapers don't share field names for the same kind of
data — and these have already changed once as the uploaded files were
swapped for updated versions:

| Source | Fields it currently emits |
|---|---|
| ANY.RUN | `record_number`, `malware_name`, `type`, `trend_url`, `report_url` |
| Malpedia | `record_number`, `malware_name`, `operating_system`, `link` |
| ThreatFox | `record_number`, `malware_name`, `tags`, `reporter`, `ioc`, `record_link` |

Rather than forcing all three into one fixed column set (which would
either hide fields two of the sources don't share, like ThreatFox's
`tags`/`reporter`/`ioc`, or pad the others with columns they never
populate), the table's columns are read directly off whatever the
scraper for that tab actually produced — so "complete information as in
each file" holds literally, per source. The link column isn't
name-matched either: any cell whose value is itself an `http(s)` URL is
rendered as a clickable "Open ↗" link back to the source site, rather
than the dashboard needing to know that this field is called
`record_link` here and `link` there — which also means ANY.RUN's two
link columns (`trend_url` and `report_url`) both render as links
automatically, and a future rename of either field won't silently stop
working. CSV export mirrors the same per-source columns (fieldnames are
the union of keys the scraper's own records used); JSON export is the
scraped list as-is (already unwrapped if it came wrapped).

A blank field shows as `—` in the table rather than an empty cell, so
it's clear the source didn't provide that value rather than it being a
rendering bug.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # venv\Scripts\activate on Windows
pip install -r requirements.txt
playwright install chromium
python -m nltk.downloader punkt punkt_tab   # needed for newspaper3k's .nlp() summarizer
```

Run it:

```bash
python app.py
```

Then open http://127.0.0.1:5000.

## Notes

- **X auth_token**: paste the `auth_token` cookie value from a logged-in
  x.com browser session into the field on the X panel. It's held in
  memory for the duration of that one request only.
- **Rate limits & ToS**: these scrapers drive a real headless browser
  against each site. Keep request counts and run frequency reasonable,
  and check each platform's terms before scraping at scale.
- **Single-user, local tool**: results are cached in memory per platform
  (for the export buttons) and reset when you restart `app.py`. There's
  no database, auth, or multi-user support — it's meant to run on your
  own machine.
- If a scraper's target site changes its layout, that scraper's own
  code (not the dashboard) will need updating — errors are shown
  inline in the panel's status line rather than crashing the app.
- **Unit 42** launches its browser with `headless=False` (unlike most
  other scrapers here), so running it will pop open a visible Chromium
  window on the machine running `app.py` — expected, not a bug.
- **ThreatFox is not fully automatic.** Its scraper opens a visible
  (non-headless) browser, and if `threatfox.abuse.ch` shows an hCaptcha
  it will print instructions and then pause, waiting for you to solve
  the CAPTCHA in that browser window and press Enter **in the terminal
  running `app.py`** — the Flask request stays open (spinner showing)
  until you do. This is the scraper's own design, not a dashboard bug;
  keep an eye on that terminal after clicking "Run scrape" for it.
- **ANY.RUN** is the slowest Trending Malware tab: after the initial
  table scrape, it visits every family's page (and, in this version,
  looks for a public sample report) to fill in `type` and find a
  `report_url`, so a run against 20 records makes many additional page
  loads with a short delay between each. It no longer reports an `os`
  column — that was dropped when the uploaded file was last updated.
