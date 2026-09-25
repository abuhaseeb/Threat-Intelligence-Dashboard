import asyncio
import json
import os
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError


# ============================================================
# CONFIGURATION
# ============================================================

BLOG_URL = "https://research.intezer.com/blog/"
OUTPUT_FILE = "output/intezer_latest_10_blogs.json"

NUMBER_OF_BLOGS = 10

HEADLESS = True

# Small delay between requests
REQUEST_DELAY = 1.0


# ============================================================
# REGEX PATTERNS FOR IOC EXTRACTION
# ============================================================

IOC_PATTERNS = {

    # IPv4 address
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),

    # MD5
    "md5": re.compile(
        r"\b[a-fA-F0-9]{32}\b"
    ),

    # SHA1
    "sha1": re.compile(
        r"\b[a-fA-F0-9]{40}\b"
    ),

    # SHA256
    "sha256": re.compile(
        r"\b[a-fA-F0-9]{64}\b"
    ),

    # CVE
    "cve": re.compile(
        r"\bCVE-\d{4}-\d{4,7}\b",
        re.IGNORECASE
    ),

    # Email
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    ),

    # HTTP/HTTPS URLs
    "url": re.compile(
        r"https?://[^\s<>'\"`)\]]+",
        re.IGNORECASE
    ),

    # Domains
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9-]+\.)+"
        r"(?:com|net|org|info|biz|io|co|ai|dev|app|xyz|me|"
        r"online|site|cloud|tech|us|uk|de|ru|cn|top|pro|"
        r"live|shop|store|website|digital|services)\b",
        re.IGNORECASE
    ),

    # Windows paths
    "windows_path": re.compile(
        r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"
    ),

    # Unix/Linux paths
    "unix_path": re.compile(
        r"(?<![\w.-])/(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+"
    ),
}


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def clean_text(text):
    """
    Clean excessive whitespace while preserving readable content.
    """
    if not text:
        return ""

    text = text.replace("\xa0", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)

    return text.strip()


def unique_list(items):
    """
    Preserve order while removing duplicates.
    """
    seen = set()
    result = []

    for item in items:
        if not item:
            continue

        item = item.strip()

        if item and item not in seen:
            seen.add(item)
            result.append(item)

    return result


def normalize_ioc(value):
    """
    Normalize common defanged IOC formats.

    Examples:
        example[.]com -> example.com
        hxxp:// -> http://
        1[.]2[.]3[.]4 -> 1.2.3.4
    """
    value = value.strip()

    value = value.replace("[.]", ".")
    value = value.replace("(.)", ".")
    value = value.replace("{.}", ".")

    value = re.sub(
        r"(?i)^hxxps://",
        "https://",
        value
    )

    value = re.sub(
        r"(?i)^hxxp://",
        "http://",
        value
    )

    return value


def extract_iocs(text):
    """
    Extract IOCs from article text.
    """

    iocs = {
        "ipv4": [],
        "domains": [],
        "urls": [],
        "md5": [],
        "sha1": [],
        "sha256": [],
        "emails": [],
        "cves": [],
        "windows_paths": [],
        "unix_paths": []
    }

    if not text:
        return iocs

    # IPv4
    for value in IOC_PATTERNS["ipv4"].findall(text):
        # Avoid impossible/common non-IOC values
        try:
            parts = [int(x) for x in value.split(".")]

            if len(parts) == 4 and all(0 <= x <= 255 for x in parts):
                iocs["ipv4"].append(value)

        except Exception:
            pass

    # SHA256
    iocs["sha256"].extend(
        IOC_PATTERNS["sha256"].findall(text)
    )

    # SHA1
    iocs["sha1"].extend(
        IOC_PATTERNS["sha1"].findall(text)
    )

    # MD5
    iocs["md5"].extend(
        IOC_PATTERNS["md5"].findall(text)
    )

    # CVEs
    iocs["cves"].extend(
        x.upper()
        for x in IOC_PATTERNS["cve"].findall(text)
    )

    # Emails
    iocs["emails"].extend(
        IOC_PATTERNS["email"].findall(text)
    )

    # URLs
    urls = IOC_PATTERNS["url"].findall(text)

    for url in urls:
        url = url.rstrip(".,;:)]}>\"'")

        iocs["urls"].append(
            normalize_ioc(url)
        )

    # Domains
    domains = IOC_PATTERNS["domain"].findall(text)

    for domain in domains:
        iocs["domains"].append(
            normalize_ioc(domain)
        )

    # Windows paths
    iocs["windows_paths"].extend(
        IOC_PATTERNS["windows_path"].findall(text)
    )

    # Unix paths
    iocs["unix_paths"].extend(
        IOC_PATTERNS["unix_path"].findall(text)
    )

    # Remove duplicates
    for key in iocs:
        iocs[key] = unique_list(iocs[key])

    return iocs


# ============================================================
# PAGE HELPERS
# ============================================================

async def safe_text(locator):
    """
    Safely get text from a locator.
    """
    try:
        if await locator.count() > 0:
            return clean_text(await locator.first.inner_text())
    except Exception:
        pass

    return ""


async def first_existing_text(page, selectors):
    """
    Try multiple CSS selectors and return first useful text.
    """

    for selector in selectors:

        try:
            locator = page.locator(selector)

            if await locator.count() > 0:

                text = await locator.first.inner_text()

                text = clean_text(text)

                if text:
                    return text

        except Exception:
            continue

    return ""


# ============================================================
# GET BLOG LINKS FROM BLOG INDEX
# ============================================================

async def get_blog_links(page):
    """
    Collect individual blog article URLs from the Intezer blog
    index and pagination pages.
    """

    blog_links = []
    visited_pages = set()

    current_page_url = BLOG_URL

    while len(blog_links) < NUMBER_OF_BLOGS:

        if current_page_url in visited_pages:
            break

        visited_pages.add(current_page_url)

        print(f"\nOpening blog listing: {current_page_url}")

        try:
            await page.goto(
                current_page_url,
                wait_until="domcontentloaded",
                timeout=60000
            )

            await page.wait_for_timeout(1500)

        except PlaywrightTimeoutError:
            print("Page timeout. Continuing...")

        except Exception as e:
            print(f"Could not open listing page: {e}")
            break

        # ----------------------------------------------------
        # Find all links
        # ----------------------------------------------------

        links = await page.locator("a").evaluate_all(
            """
            elements => elements.map(a => ({
                href: a.href,
                text: (a.innerText || a.textContent || "").trim()
            }))
            """
        )

        for item in links:

            href = item.get("href", "")
            text = clean_text(item.get("text", ""))

            if not href:
                continue

            # Only Intezer blog URLs
            if not href.startswith("https://research.intezer.com/blog/"):
                continue

            # Ignore index/pagination itself
            path = urlparse(href).path.rstrip("/")

            if path == "/blog":
                continue

            if re.match(
                r"^/blog/page/\d+$",
                path
            ):
                continue

            # Ignore anchors
            href = href.split("#")[0]

            if href not in blog_links:
                blog_links.append(href)

                print(
                    f"Found blog #{len(blog_links)}: "
                    f"{text[:100]}"
                )

            if len(blog_links) >= NUMBER_OF_BLOGS:
                break

        if len(blog_links) >= NUMBER_OF_BLOGS:
            break

        # ----------------------------------------------------
        # Find next page
        # ----------------------------------------------------

        next_url = None

        try:
            next_candidates = await page.locator(
                "a"
            ).evaluate_all(
                """
                elements => elements.map(a => ({
                    href: a.href,
                    text: (a.innerText || a.textContent || "").trim(),
                    rel: a.rel || "",
                    aria: a.getAttribute("aria-label") || ""
                }))
                """
            )

            for item in next_candidates:

                href = item.get("href", "")
                text = item.get("text", "").lower()
                rel = item.get("rel", "").lower()
                aria = item.get("aria", "").lower()

                if not href:
                    continue

                if (
                    rel == "next"
                    or "next" in text
                    or "older" in text
                    or "next" in aria
                ):
                    if "/blog/page/" in href:
                        next_url = href
                        break

        except Exception:
            pass

        if not next_url:
            break

        current_page_url = next_url

    return blog_links[:NUMBER_OF_BLOGS]


# ============================================================
# EXTRACT ARTICLE CONTENT
# ============================================================

async def extract_article(page, url, index):
    """
    Open an individual Intezer blog article and extract
    complete article information.
    """

    print("\n" + "=" * 70)
    print(f"Scraping blog {index}")
    print(url)
    print("=" * 70)

    try:
        await page.goto(
            url,
            wait_until="domcontentloaded",
            timeout=60000
        )

    except PlaywrightTimeoutError:
        print("Article page timeout. Trying to continue...")

    except Exception as e:
        print(f"Failed to open article: {e}")
        return None

    await page.wait_for_timeout(1200)

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    title = await first_existing_text(
        page,
        [
            "article h1",
            "main h1",
            "h1",
            ".entry-title",
            ".post-title"
        ]
    )

    # --------------------------------------------------------
    # AUTHOR
    # --------------------------------------------------------

    author = await first_existing_text(
        page,
        [
            "article .author",
            "article [class*='author']",
            "main [class*='author']",
            "[rel='author']",
            ".byline"
        ]
    )

    # If selector gives "By Author", clean it
    if author:
        author = re.sub(
            r"^\s*By\s+",
            "",
            author,
            flags=re.IGNORECASE
        ).strip()

    # --------------------------------------------------------
    # DATE
    # --------------------------------------------------------

    publication_date = ""

    date_selectors = [
        "article time",
        "main time",
        "time[datetime]",
        "[class*='date']",
        "[class*='published']"
    ]

    for selector in date_selectors:

        try:
            loc = page.locator(selector)

            if await loc.count() > 0:

                for i in range(
                    min(await loc.count(), 5)
                ):
                    item = loc.nth(i)

                    value = ""

                    try:
                        value = await item.get_attribute(
                            "datetime"
                        )
                    except Exception:
                        pass

                    if not value:
                        value = await item.inner_text()

                    value = clean_text(value)

                    if value:
                        publication_date = value
                        break

                if publication_date:
                    break

        except Exception:
            continue

    # --------------------------------------------------------
    # META DESCRIPTION
    # --------------------------------------------------------

    description = ""

    try:
        meta = page.locator(
            "meta[name='description']"
        )

        if await meta.count() > 0:
            description = (
                await meta.first.get_attribute("content")
                or ""
            )

            description = clean_text(description)

    except Exception:
        pass

    # Try article intro if meta description isn't useful
    if not description:

        description = await first_existing_text(
            page,
            [
                "article .excerpt",
                "article .intro",
                "article header p",
                "main .excerpt"
            ]
        )

    # --------------------------------------------------------
    # TAGS / CATEGORIES
    # --------------------------------------------------------

    tags = []

    try:

        tag_links = await page.locator(
            "article a"
        ).evaluate_all(
            """
            elements => elements.map(a => ({
                text: (a.innerText || "").trim(),
                href: a.href
            }))
            """
        )

        for item in tag_links:

            text = clean_text(
                item.get("text", "")
            )

            href = item.get("href", "")

            if not text:
                continue

            # Intezer tag URLs
            if (
                "/tag/" in href
                or "/category/" in href
            ):
                tags.append(text)

    except Exception:
        pass

    tags = unique_list(tags)

    # --------------------------------------------------------
    # FIND ARTICLE CONTAINER
    # --------------------------------------------------------

    article_locator = None

    article_selectors = [
        "article",
        "main article",
        "main .post",
        "main .entry-content",
        "main .post-content",
        "main"
    ]

    for selector in article_selectors:

        try:

            loc = page.locator(selector)

            if await loc.count() > 0:

                # Prefer the largest relevant container
                best = None
                best_length = 0

                count = await loc.count()

                for i in range(count):

                    candidate = loc.nth(i)

                    try:
                        text = await candidate.inner_text()

                        length = len(text or "")

                        if length > best_length:
                            best = candidate
                            best_length = length

                    except Exception:
                        continue

                if best is not None and best_length > 200:
                    article_locator = best
                    break

        except Exception:
            continue

    if article_locator is None:
        print("WARNING: Article container not found.")
        return None

    # --------------------------------------------------------
    # REMOVE NON-ARTICLE ELEMENTS
    # --------------------------------------------------------

    try:
        await article_locator.locator(
            """
            script,
            style,
            noscript,
            nav,
            footer,
            form,
            .share,
            .sharing,
            .social-share,
            .related-posts,
            .comments
            """
        ).evaluate_all(
            """
            elements => elements.forEach(e => e.remove())
            """
        )
    except Exception:
        pass

    # --------------------------------------------------------
    # COMPLETE ARTICLE TEXT
    # --------------------------------------------------------

    complete_text = ""

    try:
        complete_text = clean_text(
            await article_locator.inner_text()
        )
    except Exception:
        pass

    # --------------------------------------------------------
    # HEADINGS
    # --------------------------------------------------------

    headings = []

    try:

        heading_data = await article_locator.locator(
            "h1, h2, h3, h4, h5, h6"
        ).evaluate_all(
            """
            elements => elements.map(e => ({
                level: e.tagName.toLowerCase(),
                text: (e.innerText || e.textContent || "").trim()
            }))
            """
        )

        for item in heading_data:

            text = clean_text(
                item.get("text", "")
            )

            if text:

                headings.append({
                    "level": item.get("level"),
                    "text": text
                })

    except Exception:
        pass

    # --------------------------------------------------------
    # PARAGRAPHS
    # --------------------------------------------------------

    paragraphs = []

    try:

        paragraph_data = await article_locator.locator(
            "p"
        ).evaluate_all(
            """
            elements => elements.map(e =>
                (e.innerText || e.textContent || "").trim()
            )
            """
        )

        paragraphs = unique_list(
            clean_text(x)
            for x in paragraph_data
            if clean_text(x)
        )

    except Exception:
        pass

    # --------------------------------------------------------
    # LISTS
    # --------------------------------------------------------

    lists = []

    try:

        list_data = await article_locator.locator(
            "ul, ol"
        ).evaluate_all(
            """
            elements => elements.map(e => ({
                type: e.tagName.toLowerCase(),
                items: Array.from(e.querySelectorAll(":scope > li"))
                    .map(li => (li.innerText || li.textContent || "").trim())
                    .filter(Boolean)
            }))
            """
        )

        for item in list_data:

            cleaned_items = [
                clean_text(x)
                for x in item.get("items", [])
                if clean_text(x)
            ]

            if cleaned_items:

                lists.append({
                    "type": item.get("type"),
                    "items": cleaned_items
                })

    except Exception:
        pass

    # --------------------------------------------------------
    # CODE BLOCKS
    # --------------------------------------------------------

    code_blocks = []

    try:

        code_data = await article_locator.locator(
            "pre, pre code"
        ).evaluate_all(
            """
            elements => elements.map(e => ({
                tag: e.tagName.toLowerCase(),
                text: e.innerText || e.textContent || ""
            }))
            """
        )

        for item in code_data:

            code = item.get("text", "")

            if code.strip():

                code_blocks.append({
                    "code": code
                })

    except Exception:
        pass

    # --------------------------------------------------------
    # TABLES
    # --------------------------------------------------------

    tables = []

    try:

        table_data = await article_locator.locator(
            "table"
        ).evaluate_all(
            """
            tables => tables.map(table => ({
                rows: Array.from(table.querySelectorAll("tr"))
                    .map(row =>
                        Array.from(row.querySelectorAll("th, td"))
                        .map(cell =>
                            (cell.innerText || cell.textContent || "").trim()
                        )
                    )
                    .filter(row => row.length > 0)
            }))
            """
        )

        for table in table_data:

            if table.get("rows"):
                tables.append(table)

    except Exception:
        pass

    # --------------------------------------------------------
    # IMAGES
    # --------------------------------------------------------

    images = []

    try:

        image_data = await article_locator.locator(
            "img"
        ).evaluate_all(
            """
            elements => elements.map(img => ({
                src: img.currentSrc || img.src || "",
                alt: img.alt || "",
                title: img.title || "",
                width: img.width || null,
                height: img.height || null
            }))
            """
        )

        for item in image_data:

            src = item.get("src", "")

            if src:

                images.append({
                    "url": src,
                    "alt": clean_text(
                        item.get("alt", "")
                    ),
                    "title": clean_text(
                        item.get("title", "")
                    ),
                    "width": item.get("width"),
                    "height": item.get("height")
                })

    except Exception:
        pass

    # --------------------------------------------------------
    # LINKS
    # --------------------------------------------------------

    links = []

    try:

        link_data = await article_locator.locator(
            "a[href]"
        ).evaluate_all(
            """
            elements => elements.map(a => ({
                text: (a.innerText || a.textContent || "").trim(),
                href: a.href
            }))
            """
        )

        seen_links = set()

        for item in link_data:

            href = item.get("href", "")

            if not href:
                continue

            href = urljoin(url, href)

            if href in seen_links:
                continue

            seen_links.add(href)

            links.append({
                "text": clean_text(
                    item.get("text", "")
                ),
                "url": href
            })

    except Exception:
        pass

    # --------------------------------------------------------
    # ARTICLE HTML
    # --------------------------------------------------------

    article_html = ""

    try:
        article_html = await article_locator.inner_html()
    except Exception:
        pass

    # --------------------------------------------------------
    # IOC EXTRACTION
    # --------------------------------------------------------

    iocs = extract_iocs(complete_text)

    # --------------------------------------------------------
    # STRUCTURED CONTENT
    # --------------------------------------------------------

    sections = []

    try:

        elements = await article_locator.locator(
            "h2, h3, h4, p, ul, ol, pre, table, figure"
        ).evaluate_all(
            """
            elements => elements.map(e => ({
                tag: e.tagName.toLowerCase(),
                text: (e.innerText || e.textContent || "").trim(),
                html: e.outerHTML
            }))
            """
        )

        for element in elements:

            text = clean_text(
                element.get("text", "")
            )

            if not text:
                continue

            sections.append({
                "type": element.get("tag"),
                "text": text,
                "html": element.get("html", "")
            })

    except Exception:
        pass

    # --------------------------------------------------------
    # RETURN COMPLETE BLOG
    # --------------------------------------------------------

    result = {
        "scraped_at": datetime.utcnow().isoformat() + "Z",

        "source": {
            "website": "Intezer Research",
            "blog_index": BLOG_URL,
            "article_url": url
        },

        "blog": {
            "title": title,
            "author": author,
            "publication_date": publication_date,
            "description": description,
            "tags": tags
        },

        "content": {
            "complete_text": complete_text,
            "headings": headings,
            "paragraphs": paragraphs,
            "lists": lists,
            "code_blocks": code_blocks,
            "tables": tables,
            "sections": sections
        },

        "media": {
            "images": images
        },

        "links": links,

        "iocs": iocs,

        "article_html": article_html
    }

    print(f"Title: {title}")
    print(f"Author: {author}")
    print(f"Date: {publication_date}")
    print(f"Paragraphs: {len(paragraphs)}")
    print(f"Headings: {len(headings)}")
    print(f"Images: {len(images)}")
    print(f"Links: {len(links)}")

    total_iocs = sum(
        len(value)
        for value in iocs.values()
    )

    print(f"IOCs found: {total_iocs}")

    return result


# ============================================================
# MAIN SCRAPER
# ============================================================

async def main():

    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )

    async with async_playwright() as p:

        browser = await p.chromium.launch(
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
                "Chrome/139.0.0.0 Safari/537.36"
            )
        )

        # Create separate pages
        listing_page = await context.new_page()
        article_page = await context.new_page()

        # ----------------------------------------------------
        # STEP 1: GET LATEST BLOG URLS
        # ----------------------------------------------------

        print("\n" + "=" * 70)
        print("STEP 1 - Finding latest blog reports")
        print("=" * 70)

        blog_links = await get_blog_links(
            listing_page
        )

        print(
            f"\nTotal blog URLs collected: "
            f"{len(blog_links)}"
        )

        if not blog_links:
            print("No blog URLs found.")
            await browser.close()
            return

        # ----------------------------------------------------
        # STEP 2: SCRAPE EACH BLOG
        # ----------------------------------------------------

        results = []

        for index, url in enumerate(
            blog_links,
            start=1
        ):

            try:

                blog = await extract_article(
                    article_page,
                    url,
                    index
                )

                if blog:
                    blog["rank"] = index
                    results.append(blog)

            except Exception as e:

                print(
                    f"ERROR scraping {url}: {e}"
                )

            await asyncio.sleep(
                REQUEST_DELAY
            )

        # ----------------------------------------------------
        # STEP 3: SAVE JSON
        # ----------------------------------------------------

        output_data = {
            "source": "Intezer Research Blog",
            "source_url": BLOG_URL,
            "scraped_at": datetime.utcnow().isoformat() + "Z",
            "requested_reports": NUMBER_OF_BLOGS,
            "reports_scraped": len(results),
            "reports": results
        }

        with open(
            OUTPUT_FILE,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                output_data,
                f,
                indent=4,
                ensure_ascii=False
            )

        print("\n" + "=" * 70)
        print("SCRAPING COMPLETED")
        print("=" * 70)

        print(
            f"Reports scraped: {len(results)}"
        )

        print(
            f"JSON saved to: {OUTPUT_FILE}"
        )

        await browser.close()


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    asyncio.run(main())