"""
Canonical IOC extraction and normalization.

The 12 scrapers each ship their own IOC regexes, but they don't agree on
category names (ip_addresses vs ipv4_addresses vs ipv4), some lump every
hash length into one "hashes" bucket, and at least one (Recorded Future)
never extracts IOCs at all. Left as-is, the dashboard would show
different, incomplete IOC sets depending on which scraper produced the
item.

This module fixes that in two steps:

1. `canonicalize()` folds whatever IOC dict a scraper already produced
   into one fixed set of category names, classifying ambiguous "hashes"
   lists by string length.
2. `extract_from_text()` re-runs a comprehensive, defang-aware regex
   pass over the item's own title/body/description text and is unioned
   with (1), so every item gets a full IOC set regardless of whether -
   or how well - its source scraper extracted one.
"""

import re
from urllib.parse import urlparse

CANONICAL_CATEGORIES = [
    "ipv4",
    "ipv6",
    "domains",
    "urls",
    "emails",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "cves",
    "mitre_attack",
    "file_names",
    "registry_paths",
    "windows_paths",
    "unix_paths",
    "bitcoin_addresses",
]

# Maps every category name seen across the 12 scrapers onto one of the
# canonical categories above.
_KEY_ALIASES = {
    "ipv4": "ipv4",
    "ip_addresses": "ipv4",
    "ipv4_addresses": "ipv4",
    "defanged_ip": "ipv4",
    "ip": "ipv4",
    "ipv6": "ipv6",
    "ipv6_addresses": "ipv6",
    "domain": "domains",
    "domains": "domains",
    "defanged_domain": "domains",
    "url": "urls",
    "urls": "urls",
    "email": "emails",
    "emails": "emails",
    "email_addresses": "emails",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
    "cve": "cves",
    "cves": "cves",
    "cve_ids": "cves",
    "mitre_attack": "mitre_attack",
    "mitre_ids": "mitre_attack",
    "file_names": "file_names",
    "registry_paths": "registry_paths",
    "registry_keys": "registry_paths",
    "windows_registry": "registry_paths",
    "windows_path": "windows_paths",
    "windows_paths": "windows_paths",
    "unix_path": "unix_paths",
    "unix_paths": "unix_paths",
    "file_paths": "windows_paths",
    "bitcoin": "bitcoin_addresses",
    "bitcoin_addresses": "bitcoin_addresses",
}

_HASH_LENGTH_TO_CATEGORY = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

_DEFANG_SUBS = [
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\[at\]|\(at\)", re.I), "@"),
    (re.compile(r"hxxps", re.I), "https"),
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[:\]"), ":"),
]

_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"
)
_IPV6 = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
_URL = re.compile(r"\bhttps?://[^\s\"'<>\)\]]+", re.IGNORECASE)
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:xyz|com|net|org|info|biz|top|club|online|site|ru|cn|io|co|icu|shop|"
    r"live|link|click|work|gov|edu|us|uk|de|fr)\b",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA512 = re.compile(r"\b[a-fA-F0-9]{128}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def refang(text):
    """Undo common IOC defanging (hxxp, [.], [at]) so matches are usable."""
    if not text:
        return text
    for pattern, repl in _DEFANG_SUBS:
        text = pattern.sub(repl, text)
    return text


def _empty():
    return {category: [] for category in CANONICAL_CATEGORIES}


def _classify_hash(value):
    return _HASH_LENGTH_TO_CATEGORY.get(len(value))


def canonicalize(raw_ioc_dict):
    """Fold a scraper-provided IOC dict (any of the naming schemes used
    across the 12 scrapers) into the canonical category set."""
    result = _empty()
    if not isinstance(raw_ioc_dict, dict):
        return result

    for key, values in raw_ioc_dict.items():
        if not isinstance(values, list):
            continue
        key_lower = key.lower()

        if key_lower in ("hashes", "hash", "file_hashes"):
            for value in values:
                category = _classify_hash(str(value))
                if category:
                    result[category].append(value)
            continue

        category = _KEY_ALIASES.get(key_lower)
        if category:
            result[category].extend(values)
        # Unrecognized keys (e.g. a scraper's free-text "raw_text" IOC
        # block) are intentionally skipped here -- they still get swept
        # up by extract_from_text() below since that runs on the item's
        # full text, IOC block included.

    return result


def extract_from_text(text):
    """Comprehensive, defang-aware IOC sweep over free text."""
    result = _empty()
    if not text:
        return result

    cleaned = refang(text)

    urls = sorted(
        {url.rstrip(".,;:!?)]}>\"'") for url in _URL.findall(cleaned)}
    )
    emails = sorted(set(_EMAIL.findall(cleaned)))
    ipv4 = sorted(set(_IPV4.findall(cleaned)))
    ipv6 = sorted(set(m for m in _IPV6.findall(cleaned) if m.count(":") >= 2))
    md5 = sorted(set(_MD5.findall(cleaned)))
    sha1 = sorted(set(_SHA1.findall(cleaned)) - set(md5))
    sha256 = sorted(set(_SHA256.findall(cleaned)))
    sha512 = sorted(set(_SHA512.findall(cleaned)))
    cves = sorted(set(m.upper() for m in _CVE.findall(cleaned)))
    mitre = sorted(set(m.upper() for m in _MITRE.findall(cleaned)))

    domains = set()
    for url in urls:
        try:
            host = urlparse(url).hostname
            if host:
                domains.add(host.lower())
        except ValueError:
            pass
    for domain in _DOMAIN.findall(cleaned):
        domain = domain.lower().rstrip(".")
        if _IPV4.fullmatch(domain):
            continue
        if any(email.lower().endswith("@" + domain) for email in emails):
            continue
        domains.add(domain)

    result.update(
        {
            "ipv4": ipv4,
            "ipv6": ipv6,
            "domains": sorted(domains),
            "urls": urls,
            "emails": emails,
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "sha512": sha512,
            "cves": cves,
            "mitre_attack": mitre,
        }
    )
    return result


def merge(*ioc_dicts):
    """Union any number of canonical IOC dicts, deduped and sorted."""
    merged = _empty()
    for ioc_dict in ioc_dicts:
        if not ioc_dict:
            continue
        for category in CANONICAL_CATEGORIES:
            values = ioc_dict.get(category) or []
            merged[category].extend(str(v) for v in values)

    for category in CANONICAL_CATEGORIES:
        merged[category] = sorted(set(merged[category]))

    # Drop empty categories so the UI/CSV only show IOC types that were
    # actually found for this item.
    return {k: v for k, v in merged.items() if v}


def count(ioc_dict):
    return sum(len(v) for v in ioc_dict.values())


def flatten_for_csv(ioc_dict):
    """'ipv4=1.2.3.4|5.6.7.8; domains=evil.xyz; cves=CVE-2024-1234'"""
    parts = []
    for category, values in ioc_dict.items():
        if values:
            parts.append(f"{category}={'|'.join(values)}")
    return "; ".join(parts)
