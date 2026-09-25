import asyncio
import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError


# ============================================================
# CONFIGURATION
# ============================================================

INSTAGRAM_USERNAME = "hackread"

INSTAGRAM_PROFILE = (
    f"https://www.instagram.com/{INSTAGRAM_USERNAME}/"
)

OUTPUT_FILE = Path("output/hackread_posts.json")

MAX_POSTS = 10

HEADLESS = False

# Optional:
# If Instagram requires authentication, create a Playwright
# storage state and set this to "state.json".
STORAGE_STATE = None


# ============================================================
# REGEX / IOC PATTERNS
# ============================================================

IPV4_RE = re.compile(
    r"\b(?:"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\."
    r"){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

IPV6_RE = re.compile(
    r"\b(?:"
    r"(?:[0-9a-fA-F]{1,4}:){2,7}"
    r"[0-9a-fA-F]{0,4}"
    r")\b"
)

DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}"
    r"[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\b"
)

URL_RE = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE
)

EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b"
)

MD5_RE = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)

SHA1_RE = re.compile(
    r"\b[a-fA-F0-9]{40}\b"
)

SHA256_RE = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)

SHA512_RE = re.compile(
    r"\b[a-fA-F0-9]{128}\b"
)

CVE_RE = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    re.IGNORECASE
)

FILENAME_RE = re.compile(
    r"\b[\w.-]+\."
    r"(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jar|zip|rar|7z|"
    r"doc|docx|xls|xlsx|pdf|iso|img|bin|apk|dmg|pkg)\b",
    re.IGNORECASE
)

# Common cryptocurrency address patterns.
BTC_RE = re.compile(
    r"\b(?:"
    r"bc1[a-zA-HJ-NP-Z0-9]{25,87}|"
    r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}"
    r")\b"
)

ETH_RE = re.compile(
    r"\b0x[a-fA-F0-9]{40}\b"
)

SOL_RE = re.compile(
    r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b"
)


# ============================================================
# GENERAL HELPERS
# ============================================================

def unique(items):
    """Preserve order while removing duplicates."""
    result = []

    for item in items:
        if item and item not in result:
            result.append(item)

    return result


def clean_text(text):
    if not text:
        return ""

    text = re.sub(r"\s+", " ", text)
    return text.strip()


def normalize_url(url):
    if not url:
        return None

    url = url.strip()

    # Remove common punctuation accidentally captured
    url = url.rstrip(".,;:!?)]}\"'")

    return url


def extract_post_id(url):
    if not url:
        return None

    parsed = urlparse(url)

    parts = [
        p for p in parsed.path.split("/")
        if p
    ]

    # Instagram:
    # /p/POST_ID/
    # /reel/POST_ID/
    # /tv/POST_ID/
    if len(parts) >= 2 and parts[0] in {
        "p",
        "reel",
        "tv"
    }:
        return parts[1]

    # Threads:
    # /@username/post/POST_ID/
    if "threads.com" in parsed.netloc:
        if "post" in parts:
            index = parts.index("post")

            if index + 1 < len(parts):
                return parts[index + 1]

    return None


# ============================================================
# IOC EXTRACTION
# ============================================================

def extract_iocs(text):
    """
    Extract common cyber threat intelligence indicators
    from text.

    This is intentionally regex-based and should be considered
    a first-pass extractor rather than a complete CTI parser.
    """

    if not text:
        text = ""

    urls = [
        normalize_url(x)
        for x in URL_RE.findall(text)
    ]

    urls = unique(urls)

    ipv4 = unique(IPV4_RE.findall(text))
    ipv6 = unique(IPV6_RE.findall(text))

    emails = unique(
        EMAIL_RE.findall(text)
    )

    cves = unique(
        [x.upper() for x in CVE_RE.findall(text)]
    )

    md5 = unique(
        [x.lower() for x in MD5_RE.findall(text)]
    )

    sha1 = unique(
        [x.lower() for x in SHA1_RE.findall(text)]
    )

    sha256 = unique(
        [x.lower() for x in SHA256_RE.findall(text)]
    )

    sha512 = unique(
        [x.lower() for x in SHA512_RE.findall(text)]
    )

    filenames = unique(
        FILENAME_RE.findall(text)
    )

    btc = unique(
        BTC_RE.findall(text)
    )

    eth = unique(
        ETH_RE.findall(text)
    )

    # SOL_RE is intentionally conservative because this pattern
    # can produce false positives for random base58 strings.
    sol = []

    for candidate in SOL_RE.findall(text):
        if len(candidate) >= 32:
            sol.append(candidate)

    sol = unique(sol)

    # Domains
    domains = []

    for domain in DOMAIN_RE.findall(text):
        domain_lower = domain.lower()

        # Avoid treating email domains as independent IOCs
        # when they are already part of an email address.
        if not any(
            email.lower().endswith("@" + domain_lower)
            for email in emails
        ):
            domains.append(domain)

    domains = unique(domains)

    return {
        "ipv4": ipv4,
        "ipv6": ipv6,
        "domains": domains,
        "urls": urls,
        "emails": emails,

        "hashes": {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "sha512": sha512
        },

        "cves": cves,

        "crypto_wallets": {
            "bitcoin": btc,
            "ethereum": eth,
            "solana": sol
        },

        "file_names": filenames
    }


# ============================================================
# TITLE EXTRACTION
# ============================================================

def extract_title(caption):
    """
    Instagram does not necessarily have a formal 'title'.

    For security/news posts, use the first meaningful line
    as a title.
    """

    if not caption:
        return ""

    lines = [
        clean_text(line)
        for line in caption.splitlines()
        if clean_text(line)
    ]

    if not lines:
        return ""

    title = lines[0]

    # Don't create an enormous title from a caption.
    if len(title) > 200:
        title = title[:197] + "..."

    return title


# ============================================================
# INSTAGRAM POST URL DISCOVERY
# ============================================================

async def collect_instagram_post_urls(page, limit=10):
    """
    Scroll the Instagram profile and collect post/reel URLs.

    We stop after obtaining enough unique URLs.
    """

    print("[*] Opening Instagram profile...")

    await page.goto(
        INSTAGRAM_PROFILE,
        wait_until="domcontentloaded",
        timeout=60000
    )

    await page.wait_for_timeout(4000)

    post_urls = set()

    previous_count = 0
    no_growth_iterations = 0

    while len(post_urls) < limit:

        # Instagram links generally expose the post URL in href.
        links = await page.locator(
            'a[href*="/p/"], '
            'a[href*="/reel/"], '
            'a[href*="/tv/"]'
        ).all()

        for link in links:

            try:
                href = await link.get_attribute("href")
            except Exception:
                continue

            if not href:
                continue

            if (
                "/p/" not in href
                and "/reel/" not in href
                and "/tv/" not in href
            ):
                continue

            absolute = urljoin(
                "https://www.instagram.com",
                href
            )

            absolute = absolute.split("?")[0]

            post_urls.add(absolute)

        print(
            f"[*] Found {len(post_urls)} Instagram posts..."
        )

        if len(post_urls) >= limit:
            break

        # Scroll down.
        await page.mouse.wheel(0, 2500)

        await page.wait_for_timeout(2500)

        if len(post_urls) == previous_count:
            no_growth_iterations += 1
        else:
            no_growth_iterations = 0

        previous_count = len(post_urls)

        # Avoid scrolling forever.
        if no_growth_iterations >= 4:
            break

    # The profile is displayed newest-first in normal cases,
    # but sort order should not be treated as authoritative.
    return list(post_urls)[:limit]


# ============================================================
# INSTAGRAM POST EXTRACTION
# ============================================================

async def extract_instagram_post(page, url):
    """
    Open an Instagram post and extract:
      - title
      - caption/body
      - media
      - timestamp
      - hashtags
      - mentions
      - IOCs
    """

    print(f"[*] Extracting: {url}")

    await page.goto(
        url,
        wait_until="domcontentloaded",
        timeout=60000
    )

    await page.wait_for_timeout(2500)

    # --------------------------------------------------------
    # Get page metadata
    # --------------------------------------------------------

    title_meta = await page.locator(
        'meta[property="og:title"]'
    ).get_attribute("content")

    description_meta = await page.locator(
        'meta[property="og:description"]'
    ).get_attribute("content")

    image_meta = await page.locator(
        'meta[property="og:image"]'
    ).get_attribute("content")

    page_title = await page.title()

    # --------------------------------------------------------
    # Caption
    # --------------------------------------------------------

    caption = ""

    # Instagram's exact DOM changes periodically.
    # Try several possibilities.

    caption_selectors = [
        'h1',
        'article div[role="button"]',
        'article span',
        'article'
    ]

    for selector in caption_selectors:

        try:
            loc = page.locator(selector)

            count = await loc.count()

            if count == 0:
                continue

            for i in range(min(count, 20)):

                text = await loc.nth(i).inner_text(
                    timeout=3000
                )

                text = clean_text(text)

                if (
                    len(text) > len(caption)
                    and len(text) > 10
                ):
                    caption = text

        except Exception:
            continue

    # Metadata is a useful fallback.
    if not caption and description_meta:
        caption = description_meta

    # --------------------------------------------------------
    # Media
    # --------------------------------------------------------

    media = []

    # Images
    images = await page.locator(
        'article img'
    ).all()

    for img in images:

        try:
            src = await img.get_attribute("src")
            alt = await img.get_attribute("alt")

            if src:
                media.append({
                    "type": "image",
                    "url": src,
                    "alt": alt or ""
                })

        except Exception:
            pass

    # Fallback OG image
    if not media and image_meta:
        media.append({
            "type": "image",
            "url": image_meta,
            "alt": ""
        })

    # Videos
    videos = await page.locator(
        'article video'
    ).all()

    for video in videos:

        try:
            src = await video.get_attribute("src")

            if src:
                media.append({
                    "type": "video",
                    "url": src
                })

        except Exception:
            pass

    # Deduplicate media
    seen_media = set()
    clean_media = []

    for item in media:

        key = (
            item.get("type"),
            item.get("url")
        )

        if key in seen_media:
            continue

        seen_media.add(key)
        clean_media.append(item)

    media = clean_media

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    published_at = None

    time_elements = await page.locator(
        "article time"
    ).all()

    for time_element in time_elements:

        try:
            published_at = await time_element.get_attribute(
                "datetime"
            )

            if published_at:
                break

        except Exception:
            pass

    # --------------------------------------------------------
    # Hashtags and mentions
    # --------------------------------------------------------

    hashtags = unique(
        re.findall(
            r"(?<!\w)#[A-Za-z0-9_.-]+",
            caption
        )
    )

    mentions = unique(
        re.findall(
            r"(?<!\w)@[A-Za-z0-9_.-]+",
            caption
        )
    )

    # --------------------------------------------------------
    # IOCs
    # --------------------------------------------------------

    iocs = extract_iocs(caption)

    # --------------------------------------------------------
    # Structured record
    # --------------------------------------------------------

    post_id = extract_post_id(url)

    record = {
        "platform": "instagram",

        "post_id": post_id,

        "url": url,

        "published_at": published_at,

        "title": extract_title(caption),

        "post_body": caption,

        "media": media,

        "hashtags": hashtags,

        "mentions": mentions,

        "ioc_extraction": iocs,

        "metadata": {
            "og_title": title_meta,
            "og_description": description_meta,
            "page_title": page_title
        },

        "threads": []
    }

    return record


# ============================================================
# THREADS DISCOVERY
# ============================================================

async def find_threads_for_post(page, instagram_post):
    """
    Try to identify a Threads post associated with an Instagram
    post.

    IMPORTANT:
    Instagram does not guarantee a direct 1:1 relationship
    between an Instagram post and a Threads post.

    Therefore this function uses links visible from the page
    and returns [] if no relationship is discoverable.
    """

    threads = []

    # --------------------------------------------------------
    # Look for direct Threads links on Instagram
    # --------------------------------------------------------

    links = await page.locator(
        'a[href*="threads.net"], '
        'a[href*="threads.com"]'
    ).all()

    thread_urls = set()

    for link in links:

        try:
            href = await link.get_attribute("href")
        except Exception:
            continue

        if not href:
            continue

        if (
            "threads.net" in href
            or "threads.com" in href
        ):
            thread_urls.add(
                urljoin(page.url, href)
            )

    # --------------------------------------------------------
    # Extract each discovered Thread
    # --------------------------------------------------------

    for thread_url in thread_urls:

        try:
            thread = await extract_thread(
                page,
                thread_url
            )

            if thread:
                threads.append(thread)

        except Exception as exc:

            print(
                f"[!] Thread extraction failed: {exc}"
            )

    return threads


# ============================================================
# THREAD EXTRACTION
# ============================================================

async def extract_thread(page, url):
    """
    Extract a Threads post in the same schema as Instagram.
    """

    print(f"[*] Extracting Thread: {url}")

    await page.goto(
        url,
        wait_until="domcontentloaded",
        timeout=60000
    )

    await page.wait_for_timeout(2500)

    # --------------------------------------------------------
    # Metadata
    # --------------------------------------------------------

    description = await page.locator(
        'meta[property="og:description"]'
    ).get_attribute("content")

    og_image = await page.locator(
        'meta[property="og:image"]'
    ).get_attribute("content")

    # --------------------------------------------------------
    # Body
    # --------------------------------------------------------

    body = ""

    candidates = [
        'article',
        '[role="article"]',
        'main'
    ]

    for selector in candidates:

        try:

            loc = page.locator(selector)

            count = await loc.count()

            for i in range(min(count, 10)):

                text = await loc.nth(i).inner_text(
                    timeout=3000
                )

                text = clean_text(text)

                if len(text) > len(body):
                    body = text

        except Exception:
            pass

    if not body:
        body = clean_text(description or "")

    # --------------------------------------------------------
    # Media
    # --------------------------------------------------------

    media = []

    images = await page.locator(
        'article img, main img'
    ).all()

    for img in images:

        try:
            src = await img.get_attribute("src")
            alt = await img.get_attribute("alt")

            if src:
                media.append({
                    "type": "image",
                    "url": src,
                    "alt": alt or ""
                })

        except Exception:
            pass

    if not media and og_image:
        media.append({
            "type": "image",
            "url": og_image,
            "alt": ""
        })

    videos = await page.locator(
        'article video, main video'
    ).all()

    for video in videos:

        try:
            src = await video.get_attribute("src")

            if src:
                media.append({
                    "type": "video",
                    "url": src
                })

        except Exception:
            pass

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    published_at = None

    times = await page.locator(
        "time"
    ).all()

    for time_element in times:

        try:
            published_at = await time_element.get_attribute(
                "datetime"
            )

            if published_at:
                break

        except Exception:
            pass

    # --------------------------------------------------------
    # IOCs
    # --------------------------------------------------------

    iocs = extract_iocs(body)

    hashtags = unique(
        re.findall(
            r"(?<!\w)#[A-Za-z0-9_.-]+",
            body
        )
    )

    mentions = unique(
        re.findall(
            r"(?<!\w)@[A-Za-z0-9_.-]+",
            body
        )
    )

    return {
        "platform": "threads",

        "post_id": extract_post_id(url),

        "url": url,

        "published_at": published_at,

        "title": extract_title(body),

        "post_body": body,

        "media": media,

        "hashtags": hashtags,

        "mentions": mentions,

        "ioc_extraction": iocs
    }


# ============================================================
# SAVE JSON
# ============================================================

def save_json(data, filename):
    filename.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            data,
            f,
            indent=2,
            ensure_ascii=False
        )

    print(
        f"[+] JSON written to: {filename}"
    )


# ============================================================
# MAIN
# ============================================================

async def main():

    async with async_playwright() as p:

        # ----------------------------------------------------
        # Launch browser
        # ----------------------------------------------------

        browser = await p.chromium.launch(
            headless=HEADLESS
        )

        # ----------------------------------------------------
        # Browser context
        # ----------------------------------------------------

        context_kwargs = {
            "viewport": {
                "width": 1440,
                "height": 1000
            },

            "locale": "en-US",

            "timezone_id": "UTC"
        }

        # Optional authenticated storage.
        if STORAGE_STATE:
            context_kwargs[
                "storage_state"
            ] = STORAGE_STATE

        context = await browser.new_context(
            **context_kwargs
        )

        context.set_default_timeout(10000)

        page = await context.new_page()

        # ----------------------------------------------------
        # Find latest 10 posts
        # ----------------------------------------------------

        post_urls = await collect_instagram_post_urls(
            page,
            limit=MAX_POSTS
        )

        print(
            f"[+] Collected {len(post_urls)} post URLs"
        )

        results = []

        # ----------------------------------------------------
        # Extract posts
        # ----------------------------------------------------

        for index, post_url in enumerate(
            post_urls,
            start=1
        ):

            print(
                f"\n========== POST {index}/{len(post_urls)} =========="
            )

            try:

                post = await extract_instagram_post(
                    page,
                    post_url
                )

                # ------------------------------------------------
                # Threads
                # ------------------------------------------------

                try:

                    post["threads"] = (
                        await find_threads_for_post(
                            page,
                            post
                        )
                    )

                except Exception as exc:

                    print(
                        f"[!] Threads lookup failed: {exc}"
                    )

                    post["threads"] = []

                results.append(post)

            except PlaywrightTimeoutError:

                print(
                    f"[!] Timeout extracting {post_url}"
                )

            except Exception as exc:

                print(
                    f"[!] Failed {post_url}: {exc}"
                )

        # ----------------------------------------------------
        # Final JSON
        # ----------------------------------------------------

        output = {
            "schema_version": "1.0",

            "account": {
                "platform": "instagram",

                "username": INSTAGRAM_USERNAME,

                "profile_url": INSTAGRAM_PROFILE
            },

            "requested_posts": MAX_POSTS,

            "extracted_posts": len(results),

            "posts": results
        }

        save_json(
            output,
            OUTPUT_FILE
        )

        await context.close()

        await browser.close()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    asyncio.run(main())