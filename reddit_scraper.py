import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError


# ============================================================
# CONFIGURATION
# ============================================================

SUBREDDIT_URL = "https://www.reddit.com/r/MalwareAnalysis/new/"
NUMBER_OF_POSTS = 10

OUTPUT_DIR = Path("output")
OUTPUT_FILE = OUTPUT_DIR / "malwareanalysis_posts.json"

HEADLESS = False

# Number of comments/threads to collect from each post.
# Set to 0 if you don't want comments.
MAX_COMMENTS_PER_POST = 50


# ============================================================
# REGEX PATTERNS FOR IOC EXTRACTION
# ============================================================

IOC_PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    ),

    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
    ),

    "url": re.compile(
        r"\b(?:https?://|hxxps?://)[^\s<>\"]+",
        re.IGNORECASE
    ),

    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}\b"
    ),

    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),

    "md5": re.compile(
        r"\b[a-fA-F0-9]{32}\b"
    ),

    "sha1": re.compile(
        r"\b[a-fA-F0-9]{40}\b"
    ),

    "sha256": re.compile(
        r"\b[a-fA-F0-9]{64}\b"
    ),

    "sha512": re.compile(
        r"\b[a-fA-F0-9]{128}\b"
    ),

    "cve": re.compile(
        r"\bCVE-\d{4}-\d{4,7}\b",
        re.IGNORECASE
    ),

    "bitcoin": re.compile(
        r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{11,71}"
        r"|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"
    ),

    "windows_registry": re.compile(
        r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC)"
        r"\\[^\s\"']+",
        re.IGNORECASE
    )
}


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def clean_text(text):
    """Clean excessive whitespace while preserving paragraphs."""

    if not text:
        return ""

    text = text.replace("\r\n", "\n")
    text = text.replace("\r", "\n")

    lines = []

    for line in text.split("\n"):
        line = re.sub(r"[ \t]+", " ", line).strip()

        if line:
            lines.append(line)

    return "\n".join(lines)


def unique_list(items):
    """Remove duplicates while preserving order."""

    result = []
    seen = set()

    for item in items:
        item = item.strip()

        if item and item not in seen:
            seen.add(item)
            result.append(item)

    return result


def extract_iocs(text):
    """
    Extract common malware-analysis/security IOCs
    from a block of text.
    """

    if not text:
        return {
            "ipv4": [],
            "ipv6": [],
            "domains": [],
            "urls": [],
            "emails": [],
            "md5": [],
            "sha1": [],
            "sha256": [],
            "sha512": [],
            "cve": [],
            "bitcoin": [],
            "windows_registry": []
        }

    # URLs first because domains may also occur inside URLs.
    urls = IOC_PATTERNS["url"].findall(text)

    # Remove trailing punctuation from URLs.
    cleaned_urls = []

    for url in urls:
        url = url.rstrip(".,;:!?)]}\"'")

        if url:
            cleaned_urls.append(url)

    domains = IOC_PATTERNS["domain"].findall(text)

    # Remove domains that are already part of URLs.
    filtered_domains = []

    for domain in domains:
        if not any(domain in url for url in cleaned_urls):
            filtered_domains.append(domain)

    return {
        "ipv4": unique_list(IOC_PATTERNS["ipv4"].findall(text)),
        "ipv6": unique_list(IOC_PATTERNS["ipv6"].findall(text)),
        "domains": unique_list(filtered_domains),
        "urls": unique_list(cleaned_urls),
        "emails": unique_list(IOC_PATTERNS["email"].findall(text)),
        "md5": unique_list(IOC_PATTERNS["md5"].findall(text)),
        "sha1": unique_list(IOC_PATTERNS["sha1"].findall(text)),
        "sha256": unique_list(IOC_PATTERNS["sha256"].findall(text)),
        "sha512": unique_list(IOC_PATTERNS["sha512"].findall(text)),
        "cve": unique_list(
            [x.upper() for x in IOC_PATTERNS["cve"].findall(text)]
        ),
        "bitcoin": unique_list(IOC_PATTERNS["bitcoin"].findall(text)),
        "windows_registry": unique_list(
            IOC_PATTERNS["windows_registry"].findall(text)
        )
    }


def determine_post_type(post_data):
    """
    Determine Reddit post type from Reddit's visible data.
    """

    if post_data.get("is_video"):
        return "video"

    if post_data.get("gallery_data"):
        return "gallery"

    if post_data.get("post_hint"):
        hint = post_data["post_hint"]

        mapping = {
            "image": "image",
            "hosted:video": "video",
            "rich:video": "video",
            "link": "link",
            "self": "self"
        }

        return mapping.get(hint, hint)

    if post_data.get("is_self"):
        return "self"

    if post_data.get("url"):
        return "link"

    return "unknown"


# ============================================================
# EXTRACT POST LINKS FROM SUBREDDIT PAGE
# ============================================================

async def collect_post_links(page):

    print("\nOpening subreddit:")

    print(SUBREDDIT_URL)

    await page.goto(
        SUBREDDIT_URL,
        wait_until="domcontentloaded",
        timeout=60000
    )

    await page.wait_for_timeout(5000)

    # Handle Reddit's cookie/banner dialogs if present.
    possible_buttons = [
        "button:has-text('Accept all')",
        "button:has-text('Accept')",
        "button:has-text('Continue')",
        "button:has-text('I agree')"
    ]

    for selector in possible_buttons:
        try:
            button = page.locator(selector).first

            if await button.is_visible(timeout=1000):
                await button.click()
                await page.wait_for_timeout(1000)
                break

        except Exception:
            pass

    links = []

    # We perform several scrolls because Reddit may lazy-load posts.
    for scroll_number in range(8):

        print(f"Scrolling subreddit page: {scroll_number + 1}/8")

        anchors = await page.locator(
            "a[href*='/r/MalwareAnalysis/comments/']"
        ).all()

        for anchor in anchors:

            try:
                href = await anchor.get_attribute("href")

                if not href:
                    continue

                href = urljoin("https://www.reddit.com", href)

                # Remove query parameters/fragments.
                href = href.split("?")[0]
                href = href.split("#")[0]

                # Reddit post URLs normally contain:
                # /r/MalwareAnalysis/comments/<id>/<slug>/
                if "/r/MalwareAnalysis/comments/" in href:

                    if href not in links:
                        links.append(href)

            except Exception:
                continue

        if len(links) >= NUMBER_OF_POSTS:
            break

        await page.mouse.wheel(0, 1800)

        await page.wait_for_timeout(2500)

    print(f"Found {len(links)} candidate post URLs.")

    return links[:NUMBER_OF_POSTS]


# ============================================================
# EXTRACT POST DATA FROM REDDIT PAGE
# ============================================================

async def extract_post(page, post_url, post_number):

    print("\n" + "=" * 70)

    print(f"Extracting post {post_number}/{NUMBER_OF_POSTS}")

    print(post_url)

    print("=" * 70)

    try:

        await page.goto(
            post_url,
            wait_until="domcontentloaded",
            timeout=60000
        )

    except PlaywrightTimeoutError:

        print("Warning: page navigation timed out.")

    await page.wait_for_timeout(4000)

    # --------------------------------------------------------
    # Extract Reddit JSON-LD / script data when available.
    # --------------------------------------------------------

    page_data = {}

    try:

        scripts = await page.locator(
            'script[type="application/ld+json"]'
        ).all()

        for script in scripts:

            try:

                text = await script.text_content()

                if text and "headline" in text:

                    data = json.loads(text)

                    if isinstance(data, dict):
                        page_data = data
                        break

            except Exception:
                pass

    except Exception:
        pass

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    title = ""

    title_selectors = [
        "shreddit-post h1",
        "h1[slot='title']",
        "h1"
    ]

    for selector in title_selectors:

        try:

            locator = page.locator(selector).first

            if await locator.count():

                title = clean_text(
                    await locator.inner_text()
                )

                if title:
                    break

        except Exception:
            pass

    # --------------------------------------------------------
    # AUTHOR
    # --------------------------------------------------------

    author = ""

    author_selectors = [
        "shreddit-post [slot='post-author']",
        "a[href^='/user/']",
        "a[href^='/u/']"
    ]

    for selector in author_selectors:

        try:

            locator = page.locator(selector).first

            if await locator.count():

                author = clean_text(
                    await locator.inner_text()
                )

                if author:
                    break

        except Exception:
            pass

    # --------------------------------------------------------
    # POST BODY / SELFTEXT
    # --------------------------------------------------------

    selftext = ""

    body_selectors = [
        "shreddit-post [slot='text-body']",
        "div[data-testid='post-content']",
        "div[data-click-id='text']",
        "shreddit-post"
    ]

    for selector in body_selectors:

        try:

            locator = page.locator(selector).first

            if await locator.count():

                candidate = clean_text(
                    await locator.inner_text()
                )

                # Avoid taking the entire post component
                # when it contains only metadata.
                if candidate and len(candidate) > 10:

                    selftext = candidate

                    break

        except Exception:
            pass

    # --------------------------------------------------------
    # POST TYPE
    # --------------------------------------------------------

    post_type = "unknown"

    if await page.locator(
        "shreddit-post"
    ).count():

        post_element = page.locator(
            "shreddit-post"
        ).first

        try:

            post_type_attr = await post_element.get_attribute(
                "post-type"
            )

            if post_type_attr:
                post_type = post_type_attr

        except Exception:
            pass

    # Detect by visible content.
    if post_type == "unknown":

        if await page.locator(
            "shreddit-post video"
        ).count():

            post_type = "video"

        elif await page.locator(
            "shreddit-post img"
        ).count():

            post_type = "image"

        elif selftext:

            post_type = "self"

    # --------------------------------------------------------
    # MEDIA
    # --------------------------------------------------------

    media = []

    # Images
    try:

        images = await page.locator(
            "shreddit-post img"
        ).all()

        for image in images:

            src = await image.get_attribute("src")

            if src and src.startswith("http"):

                media.append({
                    "type": "image",
                    "url": src
                })

    except Exception:
        pass

    # Videos
    try:

        videos = await page.locator(
            "shreddit-post video"
        ).all()

        for video in videos:

            src = await video.get_attribute("src")

            if src:

                media.append({
                    "type": "video",
                    "url": src
                })

            else:

                source = video.locator("source").first

                if await source.count():

                    src = await source.get_attribute("src")

                    if src:

                        media.append({
                            "type": "video",
                            "url": src
                        })

    except Exception:
        pass

    # Links
    try:

        links = await page.locator(
            "shreddit-post a[href]"
        ).all()

        for link in links:

            href = await link.get_attribute("href")

            if not href:
                continue

            if href.startswith("http"):

                if "reddit.com" not in href:

                    media.append({
                        "type": "external_link",
                        "url": href
                    })

    except Exception:
        pass

    # Remove duplicate media.
    unique_media = []

    seen_media = set()

    for item in media:

        key = (
            item.get("type"),
            item.get("url")
        )

        if key not in seen_media:

            seen_media.add(key)
            unique_media.append(item)

    media = unique_media

    # --------------------------------------------------------
    # METADATA
    # --------------------------------------------------------

    score = None
    comment_count = None
    created_time = None
    subreddit = "MalwareAnalysis"
    post_id = ""
    permalink = post_url
    flair = None
    nsfw = False
    spoiler = False

    try:

        post = page.locator(
            "shreddit-post"
        ).first

        if await post.count():

            post_id = (
                await post.get_attribute("id")
                or ""
            )

            score_value = await post.get_attribute("score")

            if score_value:
                try:
                    score = int(score_value)
                except Exception:
                    pass

            comment_value = await post.get_attribute(
                "comment-count"
            )

            if comment_value:

                try:
                    comment_count = int(comment_value)

                except Exception:
                    pass

            created_value = await post.get_attribute(
                "created-timestamp"
            )

            if created_value:
                created_time = created_value

            flair_value = await post.get_attribute(
                "flair"
            )

            if flair_value:
                flair = flair_value

            nsfw_value = await post.get_attribute(
                "nsfw"
            )

            if nsfw_value:
                nsfw = nsfw_value.lower() == "true"

            spoiler_value = await post.get_attribute(
                "spoiler"
            )

            if spoiler_value:
                spoiler = spoiler_value.lower() == "true"

    except Exception:
        pass

    # --------------------------------------------------------
    # EXTRACT ALL POST TEXT FOR IOC ANALYSIS
    # --------------------------------------------------------

    try:

        complete_post_text = clean_text(
            await page.locator("body").inner_text()
        )

    except Exception:

        complete_post_text = selftext

    # Combine title + body + external links.
    ioc_source_text = "\n".join([
        title,
        selftext,
        complete_post_text
    ])

    iocs = extract_iocs(ioc_source_text)

    # --------------------------------------------------------
    # COMMENTS / THREADS
    # --------------------------------------------------------

    threads = []

    if MAX_COMMENTS_PER_POST > 0:

        try:

            # Scroll down so Reddit loads comments.
            for _ in range(4):

                await page.mouse.wheel(
                    0,
                    1800
                )

                await page.wait_for_timeout(1500)

            # Reddit's current comment elements.
            comment_elements = await page.locator(
                "shreddit-comment"
            ).all()

            for comment in comment_elements:

                if len(threads) >= MAX_COMMENTS_PER_POST:
                    break

                try:

                    comment_id = (
                        await comment.get_attribute("thingid")
                        or await comment.get_attribute("id")
                        or ""
                    )

                    comment_author = ""

                    author_locator = comment.locator(
                        "a[href^='/user/'], a[href^='/u/']"
                    ).first

                    if await author_locator.count():

                        comment_author = clean_text(
                            await author_locator.inner_text()
                        )

                    comment_body = ""

                    body_locator = comment.locator(
                        "[slot='comment']"
                    ).first

                    if await body_locator.count():

                        comment_body = clean_text(
                            await body_locator.inner_text()
                        )

                    if not comment_body:

                        try:

                            comment_body = clean_text(
                                await comment.inner_text()
                            )

                        except Exception:
                            comment_body = ""

                    if not comment_body:
                        continue

                    comment_iocs = extract_iocs(
                        comment_body
                    )

                    threads.append({
                        "comment_id": comment_id,
                        "author": comment_author,
                        "body": comment_body,
                        "iocs": comment_iocs
                    })

                except Exception:
                    continue

        except Exception as e:

            print(
                f"Could not extract comments: {e}"
            )

    # --------------------------------------------------------
    # CROSSPOST INFORMATION
    # --------------------------------------------------------

    crosspost = None

    try:

        crosspost_element = page.locator(
            "shreddit-post"
        ).first

        crosspost_parent = await crosspost_element.get_attribute(
            "crosspost-parent"
        )

        if crosspost_parent:

            crosspost = {
                "parent_id": crosspost_parent
            }

    except Exception:
        pass

    # --------------------------------------------------------
    # FINAL STRUCTURED OBJECT
    # --------------------------------------------------------

    result = {
        "reddit_post": {
            "post_id": post_id,
            "subreddit": subreddit,
            "title": title,
            "author": author,
            "post_url": permalink,
            "created_at": created_time,
            "score": score,
            "comment_count": comment_count,
            "flair": flair,
            "nsfw": nsfw,
            "spoiler": spoiler
        },

        "title": title,

        "author": author,

        "post_body_selftext": selftext,

        "post_type": post_type,

        "media": media,

        "iocs": iocs,

        "threads": threads,

        "crosspost": crosspost,

        "scraped_at": datetime.now(
            timezone.utc
        ).isoformat()
    }

    return result


# ============================================================
# SAVE JSON
# ============================================================

def save_json(data):

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=4,
            ensure_ascii=False
        )

    print("\n" + "=" * 70)

    print(
        f"JSON saved successfully:"
    )

    print(
        OUTPUT_FILE.resolve()
    )

    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

async def main():

    print("=" * 70)

    print(
        "Reddit MalwareAnalysis Playwright Scraper"
    )

    print("=" * 70)

    async with async_playwright() as playwright:

        browser = await playwright.chromium.launch(
            headless=HEADLESS
        )

        context = await browser.new_context(
            viewport={
                "width": 1440,
                "height": 1000
            },

            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/151.0.0.0 Safari/537.36"
            ),

            locale="en-US"
        )

        page = await context.new_page()

        # ----------------------------------------------------
        # STEP 1: Find newest post URLs
        # ----------------------------------------------------

        post_links = await collect_post_links(
            page
        )

        if not post_links:

            print(
                "No Reddit posts were found."
            )

            await browser.close()

            return

        print(
            f"\nPreparing to scrape "
            f"{len(post_links)} posts..."
        )

        # ----------------------------------------------------
        # STEP 2: Extract each post
        # ----------------------------------------------------

        results = []

        for index, post_url in enumerate(
            post_links,
            start=1
        ):

            try:

                post_data = await extract_post(
                    page,
                    post_url,
                    index
                )

                results.append(
                    post_data
                )

                print(
                    f"Successfully extracted "
                    f"post {index}"
                )

            except Exception as e:

                print(
                    f"Error extracting post "
                    f"{index}: {e}"
                )

            # Small delay between requests.
            await page.wait_for_timeout(
                2000
            )

        # ----------------------------------------------------
        # STEP 3: Save JSON
        # ----------------------------------------------------

        save_json(results)

        await browser.close()

        print("\nScraping completed.")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        asyncio.run(main())

    except KeyboardInterrupt:

        print(
            "\nScraper stopped by user."
        )

    except Exception as e:

        print(
            f"\nFatal error: {e}"
        )
