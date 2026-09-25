"""
Central registry of every scraper wired into the dashboard.

Each entry tells scraper_runner.py:
  - which module to import (from the scrapers/ package)
  - which function to call to kick off scraping ("entry")
  - whether that function is a coroutine
  - which module-level globals to overwrite before calling it, so the
    same script the user uploaded can be re-targeted (account, subreddit,
    result limit, auth token) from the web UI without editing the file
  - display metadata for the UI (label, category, default search value)

category is one of "social", "blog", or "trending" and decides which of
the three top-level tabs a platform appears under. "trending" platforms
(ANY.RUN, Malpedia, ThreatFox) each write a flat top-level JSON list of
records (or, for ANY.RUN, a dict with a "records" list inside -- see
normalizer.find_record_list()) rather than posts/articles, and each
uses different field names for the same kind of data (a link is
"trend_url"/"report_url" on ANY.RUN, "record_link" on ThreatFox, "link"
on Malpedia -- and these have already changed once as the uploaded
scraper files were swapped). They're rendered as a plain data table
whose columns are read directly off whatever fields the scraper
actually produced (see renderTable() in static/js/app.js). Rather than
naming a "link_field" per platform here -- which breaks every time a
source's own field names change -- the table auto-detects any cell
whose value is itself an http(s) URL and renders it as a clickable
link, so this stays correct regardless of what a given scraper calls
its link field, including sources with more than one link column.
"""

SOCIAL = "social"
BLOG = "blog"
TRENDING = "trending"

PLATFORMS = {
    # ------------------------------------------------------------------
    # Social media platforms
    # ------------------------------------------------------------------
    "x": {
        "label": "X (Twitter)",
        "category": SOCIAL,
        "module": "scrapers.x_scraper",
        "entry": "main",
        "is_async": False,
        "searchable": True,
        "default_target": "Cyberteam008",
        "target_placeholder": "username (no @)",
        "target_attr": "TARGET_USERNAME",
        "needs_auth_token": True,
        "auth_attr": "AUTH_TOKEN",
        "limit_attr": "NUMBER_OF_POSTS",
        "default_limit": 10,
        "profile_url_tmpl": "https://x.com/{target}",
    },
    "reddit": {
        "label": "Reddit",
        "category": SOCIAL,
        "module": "scrapers.reddit_scraper",
        "entry": "main",
        "is_async": True,
        "searchable": True,
        "default_target": "https://www.reddit.com/r/MalwareAnalysis/new/",
        "target_placeholder": "subreddit URL, e.g. https://www.reddit.com/r/blueteamsec/new/",
        "target_attr": "SUBREDDIT_URL",
        "needs_auth_token": False,
        "limit_attr": None,
        "default_limit": None,
        "profile_url_tmpl": "{target}",
    },
    "instagram": {
        "label": "Instagram",
        "category": SOCIAL,
        "module": "scrapers.instagram_scraper",
        "entry": "main",
        "is_async": True,
        "searchable": True,
        "default_target": "hackread",
        "target_placeholder": "username (no @)",
        "target_attr": "INSTAGRAM_USERNAME",
        "extra_attr_template": {
            "INSTAGRAM_PROFILE": "https://www.instagram.com/{target}/"
        },
        "needs_auth_token": False,
        "limit_attr": None,
        "default_limit": None,
        "profile_url_tmpl": "https://www.instagram.com/{target}/",
    },
    "mastodon": {
        "label": "Mastodon",
        "category": SOCIAL,
        "module": "scrapers.mastodon_scraper",
        "entry": "custom",  # handled specially in scraper_runner._run_mastodon
        "is_async": True,
        "searchable": True,
        "default_target": "malware_traffic@infosec.exchange",
        "target_placeholder": "account@instance",
        "needs_auth_token": False,
        "limit_attr": None,
        "default_limit": 10,
        "profile_url_tmpl": "https://{instance}/@{account}",
    },

    # ------------------------------------------------------------------
    # Security vendor / research blogs
    # ------------------------------------------------------------------
    "sophos": {
        "label": "Sophos",
        "category": BLOG,
        "module": "scrapers.sophos_scraper",
        "entry": "main",
        "is_async": True,
        "searchable": False,
        "limit_attr": "NUMBER_OF_REPORTS",
        "default_limit": 5,
    },
    "recordedfuture": {
        "label": "Recorded Future",
        "category": BLOG,
        "module": "scrapers.recordedfuture_scraper",
        "entry": "main",
        "is_async": True,
        "searchable": False,
        "limit_attr": "NUMBER_OF_REPORTS",
        "default_limit": 5,
    },
    "intezer": {
        "label": "Intezer",
        "category": BLOG,
        "module": "scrapers.intezer_scraper",
        "entry": "main",
        "is_async": True,
        "searchable": False,
        "limit_attr": "NUMBER_OF_BLOGS",
        "default_limit": 5,
    },
    "crowdstrike": {
        "label": "CrowdStrike",
        "category": BLOG,
        "module": "scrapers.crowdstrike_scraper",
        "entry": "main",
        "is_async": True,
        "searchable": False,
        "limit_attr": "NUMBER_OF_REPORTS",
        "default_limit": 5,
    },
    "ciscotalos": {
        "label": "Cisco Talos",
        "category": BLOG,
        "module": "scrapers.ciscotalos_scraper",
        "entry": "scrape_talos",
        "is_async": True,
        "searchable": False,
        "limit_attr": "NUMBER_OF_REPORTS",
        "default_limit": 5,
    },
    "checkpoint": {
        "label": "Check Point Research",
        "category": BLOG,
        "module": "scrapers.checkpoint_scraper",
        "entry": "main",
        "is_async": True,
        "searchable": False,
        "limit_attr": "NUMBER_OF_REPORTS",
        "default_limit": 5,
    },
    "malwarebytes": {
        "label": "Malwarebytes",
        "category": BLOG,
        "module": "scrapers.malwarebytes_scraper",
        "entry": "main",
        "is_async": True,
        "searchable": False,
        "limit_attr": "NUM_ARTICLES",
        "default_limit": 10,
    },
    "unit42": {
        "label": "Palo Alto Unit 42",
        "category": BLOG,
        "module": "scrapers.unit42_scraper",
        "entry": "main",
        "is_async": True,
        "searchable": False,
        "limit_attr": "NUMBER_OF_REPORTS",
        "default_limit": 5,
    },

    # ------------------------------------------------------------------
    # Trending Malware -- each writes a flat list of records (ANY.RUN
    # wraps its list in a dict -- see normalizer.find_record_list()),
    # not posts/articles, and each source uses its own field names.
    # ------------------------------------------------------------------
    "anyrun": {
        "label": "ANY.RUN",
        "category": TRENDING,
        "module": "scrapers.anyrun",
        "entry": "main",
        "is_async": True,
        "searchable": False,
        "limit_attr": "TOP_N",
        "default_limit": 20,
    },
    "malpedia": {
        "label": "Malpedia",
        "category": TRENDING,
        "module": "scrapers.malpedia",
        "entry": "scrape_malpedia",
        "is_async": True,
        "searchable": False,
        "limit_attr": "TOP_N",
        "default_limit": 20,
    },
    "threatfox": {
        "label": "ThreatFox",
        "category": TRENDING,
        "module": "scrapers.threatfox",
        "entry": "scrape_threatfox",
        "is_async": False,
        "searchable": False,
        "limit_attr": None,
        "default_limit": None,
    },
}


def platforms_by_category(category):
    return {key: cfg for key, cfg in PLATFORMS.items() if cfg["category"] == category}
