"""
Every scraper writes a slightly different JSON shape (posts / reports /
blogs / articles, author as a string vs. a dict, fields nested under a
sub-object like Intezer's "blog"/"source"/"content", etc). This module
turns whatever a scraper returned into a flat, consistent list of rows
so the UI and CSV export don't need to special-case every format.

IOC completeness: each scraper only ever returns whatever its own
regexes found, under its own category names, and Recorded Future's
scraper doesn't extract IOCs at all. Left as-is, the dashboard would
show a different, incomplete IOC set depending on which platform an
item came from. To fix that, every record's already-extracted IOCs are
canonicalized (ioc_extract.py folds the different naming schemes -
ip_addresses / ipv4_addresses / ipv4, domain / domains, cve / cves,
hashes-by-length, etc - into one schema) and then unioned with a fresh
regex sweep over the item's own text. The result, stored under
row["iocs"], is the complete de-duplicated set regardless of how
thorough the source scraper's own extraction was.

Each row keeps the platform's original record under "raw" (so nothing
is lost for JSON export) plus a normalized subset used for the table
view and CSV export:

  account, author, title, body, description, url, published,
  post_type, media_count, ioc_count, iocs (dict)
"""

from config import PLATFORMS, SOCIAL
from summarizer import summarize
import ioc_extract

LIST_KEYS = ("posts", "reports", "blogs", "articles", "results", "items", "records")

# Some scrapers (e.g. intezer_scraper.py, unit42_scraper.py) nest
# title/author/description/url/iocs under a sub-object instead of
# putting them directly on the record. Before field lookup, those
# sub-objects are merged up so _first_str()/_author_name() can find
# them without a per-platform special case; this only affects lookups,
# "raw" always keeps the original nested shape.
_NESTED_LOOKUP_KEYS = (
    "blog",
    "source",
    "content",
    "meta",
    "article",
    "metadata",
    "threat_intelligence",
)

# Every place an already-extracted IOC dict might live on a record (or,
# after nesting is flattened into `lookup`, on a nested sub-object such
# as Unit 42's threat_intelligence.iocs).
_IOC_DICT_KEYS = ("iocs", "ioc_extraction", "ioc_extraction_result")

# Every place free text worth re-scanning for IOCs might live, including
# a nested article body (Intezer's content.complete_text, Unit 42's
# content.full_text) and the raw text of an IOC section a scraper
# extracted but didn't fully parse (Malwarebytes' iocs.raw_text).
_TEXT_KEYS = (
    "title",
    "post_body_selftext",
    "post_body",
    "full_content",
    "complete_text",
    "full_text",
    "main_content",
    "content",
    "body",
    "description",
    "summary",
)


def _find_records(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in LIST_KEYS:
            value = data.get(key)
            if isinstance(value, list):
                return value
        for value in data.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value
    return []


# Public alias for callers outside this module (app.py's Trending
# Malware branch) that need the same "unwrap however this scraper
# packaged its list" logic but don't want the card/IOC normalization
# the rest of this module does -- e.g. ANY.RUN writes
# {"source": ..., "records": [...]}, while Malpedia/ThreatFox write a
# bare list. Both need to come out as a plain list of dicts.
find_record_list = _find_records


def _flatten_for_lookup(record):
    """Merge known nested sub-objects (blog/source/content/...) up to
    top level for field lookup purposes. Top-level keys win on
    collision. Does not mutate or replace `record` itself."""
    flat = dict(record)
    for nested_key in _NESTED_LOOKUP_KEYS:
        nested = record.get(nested_key)
        if isinstance(nested, dict):
            for key, value in nested.items():
                flat.setdefault(key, value)
    return flat


def _first_str(lookup, keys, default=""):
    """Like a plain first-non-empty lookup, but only ever returns a
    string -- a nested dict/list value under one of `keys` (e.g.
    record["content"] being a sub-object rather than body text) is
    skipped rather than leaking a raw dict into the UI/CSV."""
    for key in keys:
        value = lookup.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return default


def _author_name(lookup):
    author = lookup.get("author") or lookup.get("author_name") or lookup.get("posted_by")
    if isinstance(author, dict):
        return (
            author.get("display_name")
            or author.get("name")
            or author.get("username")
            or str(author)
        )
    if isinstance(author, str) and author.strip():
        return author

    # Some scrapers (e.g. unit42_scraper.py's metadata.authors) give a
    # list of author names instead of one "author" field.
    authors = lookup.get("authors")
    if isinstance(authors, list) and authors:
        names = [a.strip() for a in authors if isinstance(a, str) and a.strip()]
        if names:
            return ", ".join(names)

    return ""


def _account_name(record, lookup, platform_key, target):
    if platform_key == "x":
        author = record.get("author")
        if isinstance(author, dict):
            return author.get("username") or target or ""
        return target or ""
    if platform_key == "mastodon":
        return record.get("author_handle") or target or ""
    if platform_key == "instagram":
        return target or ""
    if platform_key == "reddit" and target:
        parts = target.rstrip("/").split("/")
        subreddit = f"r/{parts[-2]}" if len(parts) >= 2 else target
        author = _author_name(lookup)
        return f"u/{author}" if author else subreddit
    return target or ""


def _media_count(record):
    media = record.get("media")
    if isinstance(media, dict):
        media = media.get("images") or media.get("items")
    if isinstance(media, list):
        return len(media)
    return 0


def _collect_ioc_source_text(lookup):
    """All the free text worth re-scanning for IOCs."""
    chunks = []
    for key in _TEXT_KEYS:
        value = lookup.get(key)
        if isinstance(value, str) and value:
            chunks.append(value)

    for ioc_key in _IOC_DICT_KEYS:
        ioc_value = lookup.get(ioc_key)
        if isinstance(ioc_value, dict):
            raw_text = ioc_value.get("raw_text")
            if isinstance(raw_text, str) and raw_text:
                chunks.append(raw_text)

    return "\n".join(chunks)


def _complete_iocs(lookup):
    """Canonicalized union of whatever IOCs the scraper already found
    (wherever on the record they live -- top level or nested, e.g.
    Unit 42's threat_intelligence.iocs) plus a fresh extraction pass
    over the record's own text."""
    scraper_ioc_dicts = [
        ioc_extract.canonicalize(lookup.get(key))
        for key in _IOC_DICT_KEYS
        if isinstance(lookup.get(key), dict)
    ]
    text_extracted = ioc_extract.extract_from_text(_collect_ioc_source_text(lookup))
    return ioc_extract.merge(*scraper_ioc_dicts, text_extracted)


def normalize(platform_key, raw_data, target=None, summarize_blogs=True):
    """
    Returns a list of normalized row dicts for one scrape result.
    `raw_data` is whatever scraper_runner.run_platform() returned.
    """
    cfg = PLATFORMS[platform_key]
    records = _find_records(raw_data)
    rows = []

    for record in records:
        if not isinstance(record, dict):
            continue

        lookup = _flatten_for_lookup(record)

        # IOC extraction runs on the record's own raw text BEFORE any
        # field gets overwritten below (e.g. description is replaced by
        # a newspaper3k summary further down, which can drop an IOC
        # list that lived at the bottom of the article).
        iocs = _complete_iocs(lookup)

        url = _first_str(lookup, ["url", "post_url", "article_url", "link"], "")
        body = _first_str(
            lookup,
            [
                "post_body_selftext",
                "post_body",
                "full_content",
                "complete_text",
                "full_text",
                "body",
            ],
            "",
        )
        description = _first_str(lookup, ["description", "summary", "excerpt"], "")

        if cfg["category"] != SOCIAL and summarize_blogs:
            description = summarize(url, fallback=description or body[:280])

        row = {
            "platform": platform_key,
            "platform_label": cfg["label"],
            "account": _account_name(record, lookup, platform_key, target),
            "author": _author_name(lookup) or _account_name(record, lookup, platform_key, target),
            "title": _first_str(lookup, ["title"], ""),
            "body": body,
            "description": description,
            "url": url,
            "published": _first_str(
                lookup,
                [
                    "published_date",
                    "publication_date",
                    "created_at",
                    "timestamp_utc",
                    "date",
                    "scraped_at",
                ],
                "",
            ),
            "post_type": _first_str(lookup, ["post_type", "category"], ""),
            "media_count": _media_count(record),
            "ioc_count": ioc_extract.count(iocs),
            "iocs": iocs,
            "raw": record,
        }
        rows.append(row)

    return rows


CSV_FIELDS = [
    "platform_label",
    "account",
    "author",
    "title",
    "description",
    "url",
    "published",
    "post_type",
    "media_count",
    "ioc_count",
    "iocs_csv",
]


def to_csv_row(row):
    """Flattens a normalized row for CSV export, adding the full IOC
    detail (not just the count) as one delimited column."""
    flat = dict(row)
    flat["iocs_csv"] = ioc_extract.flatten_for_csv(row["iocs"])
    return flat


def to_export_json(row):
    """Full detail for JSON export: the scraper's original record, with
    the completed/merged IOC set and count layered on top so exported
    JSON is never missing IOCs the original scraper failed to find."""
    return {
        **row["raw"],
        "iocs": row["iocs"],
        "ioc_count": row["ioc_count"],
    }
