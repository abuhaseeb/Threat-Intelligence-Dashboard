#!/usr/bin/env python3
"""
Mastodon Post Scraper + IOC Extractor
Target: @malware_traffic@infosec.exchange (public profile, no login required)

Extracts the 10 most recent posts and structures each one into JSON with:
  - Author
  - Post body (content)
  - Post type (original / reply / boost)
  - Media (attached images/videos, alt text)
  - Thread info (if the post is part of a reply chain)
  - Extracted IOCs (IPs, domains, URLs, hashes, CVEs, emails)

Requirements:
    pip install playwright --break-system-packages
    playwright install chromium

Usage:
    python3 scrape_mastodon_iocs.py
    python3 scrape_mastodon_iocs.py --account malware_traffic --instance infosec.exchange --limit 10
"""

import asyncio
import json
import re
import argparse
from datetime import datetime, timezone
from playwright.async_api import async_playwright

# ---------------------------------------------------------------------------
# IOC regex patterns
# ---------------------------------------------------------------------------
IOC_PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"
    ),
    "url": re.compile(r"\bhxxps?://[^\s\"'<>]+|\bhttps?://[^\s\"'<>]+", re.IGNORECASE),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:xyz|com|net|org|info|biz|top|club|online|site|ru|cn|io|co|icu|shop|live|link|click|work)\b",
        re.IGNORECASE,
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    # defanged IPs like 185[.]220[.]101[.]1
    "defanged_ip": re.compile(r"\b(?:\d{1,3}\[\.\]){3}\d{1,3}\b"),
    # defanged domains like example[.]com
    "defanged_domain": re.compile(
        r"\b(?:[a-zA-Z0-9-]+\[\.\])+(?:xyz|com|net|org|info|ru|cn|io|co|top|club)\b",
        re.IGNORECASE,
    ),
}


def extract_iocs(text: str) -> dict:
    """Run all IOC regexes against a block of text and return de-duplicated hits."""
    if not text:
        return {k: [] for k in IOC_PATTERNS}

    found = {}
    for name, pattern in IOC_PATTERNS.items():
        matches = sorted(set(pattern.findall(text)))
        found[name] = matches

    # Hash length disambiguation: sha256 (64) matches are also valid hex strings
    # that could double as "domains" etc. — filter obvious overlap between md5/sha1/sha256
    # isn't needed here since lengths are disjoint (32/40/64), so no extra work required.

    return found


def classify_post_type(article_data: dict) -> str:
    """Decide whether a toot is original, a reply, or a boost (reblog)."""
    if article_data.get("is_boost"):
        return "boost"
    if article_data.get("in_reply_to"):
        return "reply"
    return "original"


async def scrape_mastodon_profile(account: str, instance: str, limit: int = 10):
    profile_url = f"https://{instance}/@{account}"
    posts_out = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            )
        )
        page = await context.new_page()

        print(f"[*] Navigating to {profile_url}")
        await page.goto(profile_url, wait_until="networkidle", timeout=60000)

        # Mastodon's public profile view lists toots inside <article> / role="article"
        # elements referred to as "status" entries in the DOM. Wait for at least one.
        try:
            await page.wait_for_selector("div.entry, article, div[data-testid='status']", timeout=15000)
        except Exception:
            print("[!] Could not detect post elements — the page layout may differ. "
                  "Falling back to a broader selector wait.")

        # Scroll to load enough posts (Mastodon lazy-loads via infinite scroll)
        collected_count = 0
        max_scrolls = 15
        for i in range(max_scrolls):
            status_handles = await page.query_selector_all("div.status, article")
            collected_count = len(status_handles)
            if collected_count >= limit:
                break
            await page.mouse.wheel(0, 3000)
            await page.wait_for_timeout(1500)

        status_handles = await page.query_selector_all("div.status, article")
        print(f"[*] Found {len(status_handles)} status elements on page, taking first {limit}")

        for handle in status_handles[:limit]:
            try:
                post_data = await parse_status_element(page, handle, account, instance)
                if post_data:
                    posts_out.append(post_data)
            except Exception as e:
                print(f"[!] Failed to parse a post: {e}")
                continue

            if len(posts_out) >= limit:
                break

        await browser.close()

    return posts_out


async def parse_status_element(page, handle, account, instance):
    """Extract structured data from a single toot DOM element."""

    # --- Author ---
    author_handle = f"@{account}@{instance}"
    display_name_el = await handle.query_selector(".display-name__html, .display-name strong")
    display_name = (await display_name_el.inner_text()).strip() if display_name_el else account

    # --- Boost / reblog detection ---
    boost_el = await handle.query_selector(".status__prepend, .status-boosted")
    is_boost = boost_el is not None

    # --- Timestamp ---
    time_el = await handle.query_selector("time")
    timestamp = await time_el.get_attribute("datetime") if time_el else None

    # --- Permalink (post URL) ---
    link_el = await handle.query_selector("a.status__relative-time, a[href*='/@" + account + "/']")
    post_url = await link_el.get_attribute("href") if link_el else None
    if post_url and post_url.startswith("/"):
        post_url = f"https://{instance}{post_url}"

    # --- Body text ---
    body_el = await handle.query_selector(".status__content, .e-content")
    body_text = (await body_el.inner_text()).strip() if body_el else ""

    # --- Content warning / spoiler text ---
    cw_el = await handle.query_selector(".status__content__spoiler-link, .content-warning")
    content_warning = (await cw_el.inner_text()).strip() if cw_el else None

    # --- Media attachments ---
    media_items = []
    media_els = await handle.query_selector_all(
        ".media-gallery img, .media-gallery video, .status-card img, "
        "picture img, video source"
    )
    for m in media_els:
        src = await m.get_attribute("src") or await m.get_attribute("srcset")
        alt = await m.get_attribute("alt")
        tag = await m.evaluate("el => el.tagName.toLowerCase()")
        if src:
            media_items.append({
                "type": "video" if tag == "video" or tag == "source" else "image",
                "url": src,
                "alt_text": alt or ""
            })

    # --- In-reply-to (thread) detection ---
    # On the public profile timeline, Mastodon shows a "thread" indicator
    # or the post appears nested under a parent. We check for that visual cue.
    reply_indicator = await handle.query_selector(".status__prepend-icon, .fa-reply")
    in_reply_to = reply_indicator is not None

    # If this post is part of a thread, try opening the permalink to pull
    # the full ancestor/descendant chain (best-effort, non-blocking on failure).
    thread_posts = []
    if post_url and in_reply_to:
        thread_posts = await fetch_thread(page, post_url)

    raw_data = {
        "is_boost": is_boost,
        "in_reply_to": in_reply_to,
    }

    iocs = extract_iocs(body_text)

    structured = {
        "author": display_name,
        "author_handle": author_handle,
        "post_url": post_url,
        "timestamp_utc": timestamp,
        "content_warning": content_warning,
        "post_body": body_text,
        "post_type": classify_post_type(raw_data),
        "media": media_items,
        "is_thread": len(thread_posts) > 0,
        "thread_posts": thread_posts,
        "ioc_extraction": iocs,
        "ioc_count": sum(len(v) for v in iocs.values()),
        "scraped_at": datetime.now(timezone.utc).isoformat(),
    }
    return structured


async def fetch_thread(page, post_url, max_thread_posts=10):
    """Open a post's permalink in a new tab and pull the full thread (ancestors + replies)."""
    thread = []
    try:
        thread_page = await page.context.new_page()
        await thread_page.goto(post_url, wait_until="networkidle", timeout=30000)
        await thread_page.wait_for_selector("div.status, article", timeout=10000)

        thread_statuses = await thread_page.query_selector_all("div.status, article")
        for ts in thread_statuses[:max_thread_posts]:
            body_el = await ts.query_selector(".status__content, .e-content")
            text = (await body_el.inner_text()).strip() if body_el else ""
            time_el = await ts.query_selector("time")
            ts_datetime = await time_el.get_attribute("datetime") if time_el else None
            if text:
                thread.append({
                    "post_body": text,
                    "timestamp_utc": ts_datetime,
                    "ioc_extraction": extract_iocs(text),
                })
        await thread_page.close()
    except Exception as e:
        print(f"[!] Thread fetch failed for {post_url}: {e}")
    return thread


async def main():
    parser = argparse.ArgumentParser(description="Scrape Mastodon posts + extract IOCs")
    parser.add_argument("--account", default="malware_traffic")
    parser.add_argument("--instance", default="infosec.exchange")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--output", default="mastodon_malware_traffic_posts.json")
    args = parser.parse_args()

    print(f"[*] Scraping last {args.limit} posts from @{args.account}@{args.instance}")
    posts = await scrape_mastodon_profile(args.account, args.instance, args.limit)

    output = {
        "source": "mastodon",
        "account": f"@{args.account}@{args.instance}",
        "scrape_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "post_count": len(posts),
        "posts": posts,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"[+] Saved {len(posts)} posts to {args.output}")


if __name__ == "__main__":
    asyncio.run(main())