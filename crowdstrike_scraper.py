import asyncio
import json
import re
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError


# ============================================================
# CONFIGURATION
# ============================================================

BLOG_URL = "https://www.crowdstrike.com/en-us/blog/"
RECENT_URL = "https://www.crowdstrike.com/en-us/blog/recent-articles/"

OUTPUT_FILE = "crowdstrike_latest_5.json"

NUMBER_OF_REPORTS = 5

HEADLESS = True

DELAY_SECONDS = 1


# ============================================================
# IOC REGEX PATTERNS
# ============================================================

IOC_PATTERNS = {

    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),

    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){2,7}"
        r"[0-9a-fA-F]{1,4}\b"
    ),

    "domains": re.compile(
        r"\b(?:[a-zA-Z0-9-]+\.)+"
        r"(?:com|net|org|info|biz|io|co|ru|cn|uk|de|fr|xyz|"
        r"top|site|online|cloud|app|dev|me|tv|us|ca|in|pk|tech|live|pro)\b",
        re.IGNORECASE
    ),

    "urls": re.compile(
        r"https?://[^\s<>\"]+",
        re.IGNORECASE
    ),

    "emails": re.compile(
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

    "cves": re.compile(
        r"\bCVE-\d{4}-\d{4,7}\b",
        re.IGNORECASE
    ),

    "mitre_attack": re.compile(
        r"\bT\d{4}(?:\.\d{3})?\b"
    ),

    "file_names": re.compile(
        r"\b[\w.-]+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jar|zip|"
        r"rar|7z|doc|docx|xls|xlsx|pdf|sh|so|elf|bin)\b",
        re.IGNORECASE
    ),

    "registry_keys": re.compile(
        r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|"
        r"HKEY_CURRENT_USER|HKEY_CLASSES_ROOT)\\[^\s<>\"]+",
        re.IGNORECASE
    )
}


# ============================================================
# TEXT UTILITIES
# ============================================================

def clean_text(text):
    """Clean whitespace from text."""

    if not text:
        return ""

    text = re.sub(r"\s+", " ", text)

    return text.strip()


def unique_list(items):
    """Remove duplicate values while preserving order."""

    result = []
    seen = set()

    for item in items:

        item = item.strip()

        if not item:
            continue

        if item not in seen:

            seen.add(item)
            result.append(item)

    return result


def normalize_url(url):
    """Convert relative URL to absolute CrowdStrike URL."""

    if not url:
        return None

    url = url.strip()

    if url.startswith("/"):
        url = urljoin(BLOG_URL, url)

    url = url.split("#")[0]

    return url.rstrip("/")


# ============================================================
# CHECK CROWDSTRIKE BLOG URL
# ============================================================

def is_blog_url(url):

    if not url:
        return False

    parsed = urlparse(url)

    if parsed.netloc not in (
        "www.crowdstrike.com",
        "crowdstrike.com"
    ):
        return False

    path = parsed.path.rstrip("/")

    if not path.startswith("/en-us/blog/"):
        return False

    excluded_paths = {
        "/en-us/blog",
        "/en-us/blog/recent-articles",
        "/en-us/blog/featured-articles"
    }

    if path in excluded_paths:
        return False

    return True


# ============================================================
# IOC EXTRACTION
# ============================================================

def extract_iocs(text):

    iocs = {}

    for name, pattern in IOC_PATTERNS.items():

        matches = pattern.findall(text)

        cleaned_matches = []

        for match in matches:

            if isinstance(match, tuple):
                match = match[0]

            match = str(match).strip()

            # Remove punctuation accidentally captured
            match = match.rstrip(
                ".,;:)]}\"'"
            )

            if match:
                cleaned_matches.append(match)

        iocs[name] = unique_list(cleaned_matches)

    return iocs


# ============================================================
# DISCOVER BLOG URLS
# ============================================================

async def discover_blog_urls(page):

    print()
    print("=" * 80)
    print("OPENING CROWDSTRIKE RECENT BLOGS")
    print("=" * 80)

    try:

        await page.goto(
            RECENT_URL,
            wait_until="domcontentloaded",
            timeout=60000
        )

    except PlaywrightTimeoutError:

        print(
            "Warning: page loading timed out. "
            "Continuing..."
        )

    await page.wait_for_timeout(3000)

    # Scroll to allow dynamic content to load.
    for i in range(5):

        print(
            f"Scrolling {i + 1}/5..."
        )

        await page.mouse.wheel(
            0,
            2500
        )

        await page.wait_for_timeout(
            1000
        )

    # Extract all links.
    links = await page.locator("a").evaluate_all(
        """
        elements => elements.map(a => ({
            href: a.href || "",
            text: a.innerText || ""
        }))
        """
    )

    blog_urls = []

    for item in links:

        url = normalize_url(
            item.get("href")
        )

        if not url:
            continue

        if not is_blog_url(url):
            continue

        if url not in blog_urls:

            blog_urls.append(url)

    print()
    print(
        f"Found {len(blog_urls)} possible CrowdStrike blog URLs."
    )

    return blog_urls


# ============================================================
# EXTRACT ARTICLE
# ============================================================

async def scrape_article(page, url):

    print()
    print("-" * 80)
    print("SCRAPING ARTICLE")
    print(url)
    print("-" * 80)

    try:

        await page.goto(
            url,
            wait_until="domcontentloaded",
            timeout=60000
        )

    except PlaywrightTimeoutError:

        print(
            "Warning: article page timed out."
        )

    await page.wait_for_timeout(2000)

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    title = ""

    title_selectors = [
        "main h1",
        "article h1",
        "h1"
    ]

    for selector in title_selectors:

        try:

            locator = page.locator(
                selector
            ).first

            if await locator.count() > 0:

                value = clean_text(
                    await locator.inner_text()
                )

                if value:

                    title = value
                    break

        except Exception:
            continue

    # --------------------------------------------------------
    # META DESCRIPTION
    # --------------------------------------------------------

    description = ""

    try:

        description = await page.locator(
            'meta[name="description"]'
        ).get_attribute(
            "content"
        )

        description = clean_text(
            description
        )

    except Exception:
        pass

    # --------------------------------------------------------
    # AUTHOR
    # --------------------------------------------------------

    author = ""

    author_meta_selectors = [
        'meta[name="author"]',
        'meta[property="article:author"]'
    ]

    for selector in author_meta_selectors:

        try:

            value = await page.locator(
                selector
            ).get_attribute(
                "content"
            )

            value = clean_text(
                value
            )

            if value:

                author = value
                break

        except Exception:
            continue

    # If meta author isn't available,
    # search visible elements.
    if not author:

        author_selectors = [
            '[class*="author"]',
            '[class*="Author"]',
            '[rel="author"]'
        ]

        for selector in author_selectors:

            try:

                locator = page.locator(
                    selector
                ).first

                if await locator.count() > 0:

                    value = clean_text(
                        await locator.inner_text()
                    )

                    if value and len(value) < 500:

                        author = value
                        break

            except Exception:
                continue

    # --------------------------------------------------------
    # DATE
    # --------------------------------------------------------

    date = ""

    try:

        value = await page.locator(
            'meta[property="article:published_time"]'
        ).get_attribute(
            "content"
        )

        if value:

            date = clean_text(value)

    except Exception:
        pass

    if not date:

        try:

            locator = page.locator(
                "time"
            ).first

            if await locator.count() > 0:

                datetime_value = await locator.get_attribute(
                    "datetime"
                )

                if datetime_value:

                    date = clean_text(
                        datetime_value
                    )

                else:

                    date = clean_text(
                        await locator.inner_text()
                    )

        except Exception:
            pass

    # --------------------------------------------------------
    # CATEGORY
    # --------------------------------------------------------

    category = ""

    category_selectors = [
        'meta[property="article:section"]',
        '[class*="category"]',
        '[class*="Category"]'
    ]

    for selector in category_selectors:

        try:

            locator = page.locator(
                selector
            ).first

            if await locator.count() > 0:

                value = await locator.get_attribute(
                    "content"
                )

                if not value:

                    value = await locator.inner_text()

                value = clean_text(
                    value
                )

                if value:

                    category = value
                    break

        except Exception:
            continue

    # --------------------------------------------------------
    # FIND MAIN ARTICLE CONTAINER
    # --------------------------------------------------------

    article = None

    article_selectors = [
        "article",
        "main article",
        "main",
        '[role="main"]'
    ]

    for selector in article_selectors:

        try:

            locator = page.locator(
                selector
            ).first

            if await locator.count() > 0:

                text = clean_text(
                    await locator.inner_text()
                )

                if len(text) > 500:

                    article = locator
                    break

        except Exception:
            continue

    # Fallback
    if article is None:

        article = page.locator(
            "body"
        )

    # --------------------------------------------------------
    # REMOVE UNWANTED ELEMENTS FROM ARTICLE
    # --------------------------------------------------------

    try:

        await article.evaluate(
            """
            element => {

                const selectors = [
                    "script",
                    "style",
                    "noscript",
                    "svg",
                    "nav",
                    "footer",
                    "header",
                    "form",
                    ".cookie",
                    ".cookies",
                    ".popup",
                    ".modal"
                ];

                selectors.forEach(selector => {

                    element
                        .querySelectorAll(selector)
                        .forEach(node => node.remove());

                });
            }
            """
        )

    except Exception:
        pass

    # --------------------------------------------------------
    # FULL TEXT
    # --------------------------------------------------------

    try:

        full_text = clean_text(
            await article.inner_text()
        )

    except Exception:

        full_text = ""

    # --------------------------------------------------------
    # STRUCTURED CONTENT
    # --------------------------------------------------------

    content = []

    try:

        elements = await article.locator(
            "h1, h2, h3, h4, h5, h6, "
            "p, li, blockquote, pre"
        ).all()

        for element in elements:

            try:

                tag = await element.evaluate(
                    "el => el.tagName.toLowerCase()"
                )

                text = clean_text(
                    await element.inner_text()
                )

                if not text:
                    continue

                if tag.startswith("h"):

                    content.append({
                        "type": "heading",
                        "level": int(tag[1]),
                        "text": text
                    })

                elif tag == "p":

                    content.append({
                        "type": "paragraph",
                        "text": text
                    })

                elif tag == "li":

                    content.append({
                        "type": "list_item",
                        "text": text
                    })

                elif tag == "blockquote":

                    content.append({
                        "type": "blockquote",
                        "text": text
                    })

                elif tag == "pre":

                    content.append({
                        "type": "code",
                        "text": text
                    })

            except Exception:
                continue

    except Exception:
        pass

    # --------------------------------------------------------
    # TABLES
    # --------------------------------------------------------

    tables = []

    try:

        table_elements = await article.locator(
            "table"
        ).all()

        for table in table_elements:

            table_rows = []

            rows = await table.locator(
                "tr"
            ).all()

            for row in rows:

                cells = await row.locator(
                    "th, td"
                ).all()

                row_data = []

                for cell in cells:

                    cell_text = clean_text(
                        await cell.inner_text()
                    )

                    row_data.append(
                        cell_text
                    )

                if row_data:

                    table_rows.append(
                        row_data
                    )

            if table_rows:

                tables.append(
                    table_rows
                )

    except Exception:
        pass

    # --------------------------------------------------------
    # IMAGES
    # --------------------------------------------------------

    images = []

    try:

        image_data = await article.locator(
            "img"
        ).evaluate_all(
            """
            imgs => imgs.map(img => ({
                src: img.src || "",
                alt: img.alt || "",
                title: img.title || ""
            }))
            """
        )

        for image in image_data:

            src = image.get(
                "src",
                ""
            )

            if src:

                images.append({
                    "src": src,
                    "alt": clean_text(
                        image.get(
                            "alt",
                            ""
                        )
                    ),
                    "title": clean_text(
                        image.get(
                            "title",
                            ""
                        )
                    )
                })

    except Exception:
        pass

    # --------------------------------------------------------
    # LINKS
    # --------------------------------------------------------

    links = []

    try:

        link_data = await article.locator(
            "a"
        ).evaluate_all(
            """
            links => links.map(a => ({
                text: a.innerText || "",
                href: a.href || ""
            }))
            """
        )

        for link in link_data:

            href = link.get(
                "href",
                ""
            )

            if not href:
                continue

            links.append({
                "text": clean_text(
                    link.get(
                        "text",
                        ""
                    )
                ),
                "href": href
            })

    except Exception:
        pass

    # --------------------------------------------------------
    # IOC EXTRACTION
    # --------------------------------------------------------

    iocs = extract_iocs(
        full_text
    )

    # Don't count the article itself as an IOC URL.
    iocs["urls"] = [
        item
        for item in iocs["urls"]
        if item.rstrip("/") != url.rstrip("/")
    ]

    # --------------------------------------------------------
    # ARTICLE OBJECT
    # --------------------------------------------------------

    return {

        "source": "CrowdStrike",

        "title": title,

        "url": url,

        "author": author,

        "date": date,

        "category": category,

        "description": description,

        "iocs": iocs,

        "content": content,

        "full_text": full_text,

        "images": images,

        "links": links,

        "tables": tables
    }


# ============================================================
# MAIN
# ============================================================

async def main():

    print()
    print("=" * 80)
    print("CROWDSTRIKE BLOG SCRAPER")
    print("=" * 80)
    print()

    async with async_playwright() as playwright:

        # ----------------------------------------------------
        # START BROWSER
        # ----------------------------------------------------

        browser = await playwright.chromium.launch(
            headless=HEADLESS
        )

        context = await browser.new_context(

            viewport={
                "width": 1440,
                "height": 900
            },

            locale="en-US",

            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/151.0.0.0 Safari/537.36"
            )
        )

        page = await context.new_page()

        # ----------------------------------------------------
        # DISCOVER URLS
        # ----------------------------------------------------

        blog_urls = await discover_blog_urls(
            page
        )

        if not blog_urls:

            print()
            print(
                "ERROR: No blog URLs were discovered."
            )

            await browser.close()
            return

        # ----------------------------------------------------
        # SCRAPE ARTICLES
        # ----------------------------------------------------

        reports = []

        print()
        print(
            f"Need {NUMBER_OF_REPORTS} articles."
        )
        print()

        for index, url in enumerate(
            blog_urls,
            start=1
        ):

            if len(reports) >= NUMBER_OF_REPORTS:
                break

            print(
                f"[{index}] Checking:"
            )

            print(url)

            try:

                article = await scrape_article(
                    page,
                    url
                )

                title = article.get(
                    "title",
                    ""
                )

                full_text = article.get(
                    "full_text",
                    ""
                )

                # Make sure this is an actual
                # article and not a category/navigation page.
                if (
                    title
                    and len(full_text) > 200
                ):

                    reports.append(
                        article
                    )

                    print(
                        f"SUCCESS: {title}"
                    )

                    print(
                        f"Author: {article.get('author', '')}"
                    )

                    print(
                        f"Date: {article.get('date', '')}"
                    )

                else:

                    print(
                        "Skipped: insufficient article content."
                    )

            except Exception as e:

                print(
                    f"ERROR: {e}"
                )

            # Delay between requests
            await page.wait_for_timeout(
                DELAY_SECONDS * 1000
            )

        # ----------------------------------------------------
        # CLOSE BROWSER
        # ----------------------------------------------------

        await browser.close()

    # --------------------------------------------------------
    # CREATE OUTPUT
    # --------------------------------------------------------

    output = {

        "source": "CrowdStrike",

        "source_url": BLOG_URL,

        "scraped_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "total_reports": len(
            reports
        ),

        "reports": reports
    }

    # --------------------------------------------------------
    # SAVE JSON
    # --------------------------------------------------------

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=2,
            ensure_ascii=False
        )

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("SCRAPING COMPLETED")
    print("=" * 80)

    print(
        f"Total reports: {len(reports)}"
    )

    print(
        f"JSON file: {OUTPUT_FILE}"
    )

    print()

    for number, report in enumerate(
        reports,
        start=1
    ):

        print(
            f"{number}. {report.get('title', '')}"
        )

    print()
    print("=" * 80)


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    asyncio.run(
        main()
    )