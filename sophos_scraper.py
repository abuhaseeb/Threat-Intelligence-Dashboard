import asyncio
import json
import re
from pathlib import Path
from urllib.parse import urljoin

from playwright.async_api import async_playwright


# ============================================================
# CONFIGURATION
# ============================================================

BASE_URL = "https://www.sophos.com"
LISTING_URL = (
    "https://www.sophos.com/en-us/blog"
    "?taxonomy_blog_category=Threat+Research&page=1"
)

NUMBER_OF_REPORTS = 5

OUTPUT_DIR = Path("output")
OUTPUT_FILE = OUTPUT_DIR / "sophos_threat_research.json"


# ============================================================
# REGEX PATTERNS FOR IOC EXTRACTION
# ============================================================

IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

IPV6_PATTERN = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}"
    r"[0-9a-fA-F]{0,4}\b"
)

DOMAIN_PATTERN = re.compile(
    r"\b(?!(?:example\.com|sophos\.com)\b)"
    r"(?:[a-zA-Z0-9-]+\.)+"
    r"[a-zA-Z]{2,63}\b"
)

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+"
)

MD5_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)

SHA1_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{40}\b"
)

SHA256_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)

CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    re.IGNORECASE
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def clean_text(text):
    """
    Normalize whitespace while preserving readable paragraphs.
    """

    if not text:
        return ""

    text = text.replace("\xa0", " ")

    lines = []

    for line in text.splitlines():
        line = re.sub(r"\s+", " ", line).strip()

        if line:
            lines.append(line)

    return "\n".join(lines)


def unique(values):
    """
    Remove duplicates while preserving order.
    """

    result = []
    seen = set()

    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)

    return result


def extract_iocs(text):
    """
    Extract common IOC types from article text.
    """

    urls = unique(URL_PATTERN.findall(text))

    ipv4 = unique(IPV4_PATTERN.findall(text))

    ipv6 = unique(IPV6_PATTERN.findall(text))

    md5 = unique(MD5_PATTERN.findall(text))

    sha1 = unique(SHA1_PATTERN.findall(text))

    sha256 = unique(SHA256_PATTERN.findall(text))

    cves = unique(
        [x.upper() for x in CVE_PATTERN.findall(text)]
    )

    emails = unique(EMAIL_PATTERN.findall(text))

    domains = unique(DOMAIN_PATTERN.findall(text))

    # Remove domains that are actually part of URLs
    url_domains = set()

    for url in urls:
        match = re.search(
            r"https?://([^/:?#]+)",
            url
        )

        if match:
            url_domains.add(match.group(1).lower())

    domains = [
        domain
        for domain in domains
        if domain.lower() not in url_domains
    ]

    return {
        "ipv4": ipv4,
        "ipv6": ipv6,
        "domains": domains,
        "urls": urls,
        "hashes_md5": md5,
        "hashes_sha1": sha1,
        "hashes_sha256": sha256,
        "emails": emails,
        "cves": cves
    }


# ============================================================
# ACCEPT COOKIE / CONSENT IF PRESENT
# ============================================================

async def handle_cookie_banner(page):

    possible_buttons = [
        "Accept",
        "Accept All",
        "Allow All",
        "I Agree",
        "Agree",
        "Accept Cookies"
    ]

    for text in possible_buttons:

        try:

            button = page.get_by_role(
                "button",
                name=re.compile(
                    f"^{re.escape(text)}$",
                    re.IGNORECASE
                )
            )

            if await button.count() > 0:

                await button.first.click(
                    timeout=2000
                )

                await page.wait_for_timeout(1000)

                return

        except Exception:
            pass


# ============================================================
# FIND ARTICLE LINKS
# ============================================================

async def get_article_links(page):

    print("\nOpening Sophos Threat Research listing...")
    print(LISTING_URL)

    await page.goto(
        LISTING_URL,
        wait_until="domcontentloaded",
        timeout=60000
    )

    await handle_cookie_banner(page)

    await page.wait_for_timeout(3000)

    # Scroll to allow lazy-loaded cards to appear
    for i in range(5):

        print(f"Scrolling listing page {i + 1}/5")

        await page.mouse.wheel(0, 1800)

        await page.wait_for_timeout(1200)

    # Collect links from page
    links = await page.locator("a").evaluate_all(
        """
        elements => elements.map(a => ({
            href: a.href,
            text: a.innerText
        }))
        """
    )

    article_links = []

    for item in links:

        href = item.get("href", "")
        text = clean_text(item.get("text", ""))

        if not href:
            continue

        href = urljoin(BASE_URL, href)

        # Sophos blog article URLs normally contain /en-us/blog/
        if "/en-us/blog/" not in href:
            continue

        # Ignore listing/category/tag pages
        ignored_parts = [
            "/tag/",
            "?",
            "#",
            "/category/"
        ]

        if any(part in href for part in ignored_parts):
            continue

        # Avoid duplicates
        if href not in [x["url"] for x in article_links]:

            article_links.append({
                "url": href,
                "link_text": text
            })

    print(
        f"\nFound {len(article_links)} possible article links."
    )

    return article_links


# ============================================================
# EXTRACT ARTICLE SECTIONS
# ============================================================

async def extract_sections(article):

    sections = []

    # Look for common article heading elements
    headings = article.locator(
        "h2, h3, h4"
    )

    count = await headings.count()

    for i in range(count):

        heading = headings.nth(i)

        try:

            heading_text = clean_text(
                await heading.inner_text()
            )

        except Exception:
            continue

        if not heading_text:
            continue

        content_parts = []

        # Collect following siblings until next heading
        try:

            content = await heading.evaluate(
                """
                heading => {
                    let result = [];

                    let node = heading.nextElementSibling;

                    while (node) {

                        const tag =
                            node.tagName.toLowerCase();

                        if (
                            ["h2", "h3", "h4"]
                            .includes(tag)
                        ) {
                            break;
                        }

                        const text =
                            node.innerText || "";

                        if (text.trim()) {
                            result.push(text.trim());
                        }

                        node =
                            node.nextElementSibling;
                    }

                    return result;
                }
                """
            )

            content_parts.extend(content)

        except Exception:
            pass

        section_content = clean_text(
            "\n".join(content_parts)
        )

        sections.append({
            "heading": heading_text,
            "content": section_content
        })

    return sections


# ============================================================
# EXTRACT ONE ARTICLE
# ============================================================

async def scrape_article(page, url, index):

    print("\n" + "=" * 70)
    print(f"Scraping report {index}")
    print(url)
    print("=" * 70)

    try:

        await page.goto(
            url,
            wait_until="domcontentloaded",
            timeout=60000
        )

        await handle_cookie_banner(page)

        await page.wait_for_timeout(2500)

    except Exception as e:

        print(f"ERROR opening article: {e}")

        return None

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    title = ""

    selectors = [
        "h1",
        "article h1",
        "main h1"
    ]

    for selector in selectors:

        try:

            locator = page.locator(selector)

            if await locator.count() > 0:

                title = clean_text(
                    await locator.first.inner_text()
                )

                if title:
                    break

        except Exception:
            pass

    # --------------------------------------------------------
    # DATE
    # --------------------------------------------------------

    date = ""

    date_selectors = [
        "time",
        "article time",
        "[datetime]",
        "main time"
    ]

    for selector in date_selectors:

        try:

            locator = page.locator(selector)

            if await locator.count() > 0:

                for i in range(
                    min(await locator.count(), 5)
                ):

                    element = locator.nth(i)

                    text = clean_text(
                        await element.inner_text()
                    )

                    datetime_value = await element.get_attribute(
                        "datetime"
                    )

                    if datetime_value:
                        date = datetime_value

                    elif text:
                        date = text

                    if date:
                        break

            if date:
                break

        except Exception:
            pass

    # --------------------------------------------------------
    # AUTHOR
    # --------------------------------------------------------

    author = ""

    author_selectors = [
        '[rel="author"]',
        '[class*="author"]',
        '[class*="Author"]',
        'a[href*="/author/"]'
    ]

    for selector in author_selectors:

        try:

            locator = page.locator(selector)

            if await locator.count() > 0:

                for i in range(
                    min(await locator.count(), 5)
                ):

                    text = clean_text(
                        await locator.nth(i).inner_text()
                    )

                    if text:

                        author = text
                        break

            if author:
                break

        except Exception:
            pass

    # --------------------------------------------------------
    # ARTICLE BODY
    # --------------------------------------------------------

    article = page.locator(
        "article"
    )

    if await article.count() == 0:

        article = page.locator(
            "main"
        )

    if await article.count() == 0:

        article = page.locator(
            "body"
        )

    article = article.first

    try:

        full_text = clean_text(
            await article.inner_text()
        )

    except Exception:

        full_text = ""

    # --------------------------------------------------------
    # DESCRIPTION
    # --------------------------------------------------------

    description = ""

    meta_description = page.locator(
        'meta[name="description"]'
    )

    if await meta_description.count() > 0:

        description = (
            await meta_description.first.get_attribute(
                "content"
            )
            or ""
        )

        description = clean_text(
            description
        )

    # If meta description doesn't exist,
    # use first meaningful paragraph.
    if not description:

        paragraphs = article.locator("p")

        for i in range(
            min(await paragraphs.count(), 10)
        ):

            text = clean_text(
                await paragraphs.nth(i).inner_text()
            )

            if len(text) > 50:

                description = text
                break

    # --------------------------------------------------------
    # SECTIONS
    # --------------------------------------------------------

    sections = await extract_sections(
        article
    )

    # --------------------------------------------------------
    # IOC EXTRACTION
    # --------------------------------------------------------

    iocs = extract_iocs(
        full_text
    )

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    result = {
        "title": title,
        "author": author,
        "date": date,
        "url": url,
        "category": "Threat Research",
        "description": description,
        "sections": sections,
        "iocs": iocs,
        "full_text": full_text
    }

    print(f"Title: {title}")
    print(f"Author: {author}")
    print(f"Date: {date}")
    print(
        f"Sections extracted: {len(sections)}"
    )

    total_iocs = sum(
        len(values)
        for values in iocs.values()
    )

    print(
        f"IOCs extracted: {total_iocs}"
    )

    return result


# ============================================================
# MAIN
# ============================================================

async def main():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    async with async_playwright() as p:

        print("Starting Chromium...")

        browser = await p.chromium.launch(
            headless=False,
            args=[
                "--disable-blink-features=AutomationControlled"
            ]
        )

        context = await browser.new_context(
            viewport={
                "width": 1440,
                "height": 900
            },
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/151.0.0.0 Safari/537.36"
            )
        )

        page = await context.new_page()

        try:

            # ------------------------------------------------
            # GET ARTICLE LINKS
            # ------------------------------------------------

            article_links = await get_article_links(
                page
            )

            if not article_links:

                print(
                    "No article links were found."
                )

                return

            # ------------------------------------------------
            # SCRAPE ARTICLES
            # ------------------------------------------------

            reports = []

            # Use a separate page for articles
            article_page = await context.new_page()

            for link in article_links:

                if len(reports) >= NUMBER_OF_REPORTS:
                    break

                report = await scrape_article(
                    article_page,
                    link["url"],
                    len(reports) + 1
                )

                if report:

                    # Make sure it is actually
                    # a Threat Research article.
                    text_for_check = (
                        report["title"]
                        + " "
                        + report["full_text"][:2000]
                    ).lower()

                    # Accept article if page contains
                    # Threat Research or if it came from
                    # the requested listing.
                    if (
                        "threat research"
                        in text_for_check
                        or report["title"]
                    ):
                        reports.append(report)

                await article_page.wait_for_timeout(
                    1500
                )

            await article_page.close()

            # ------------------------------------------------
            # SAVE JSON
            # ------------------------------------------------

            output_data = {
                "source": LISTING_URL,
                "category": "Threat Research",
                "requested_reports": NUMBER_OF_REPORTS,
                "reports_found": len(reports),
                "reports": reports
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
                f"Reports scraped: {len(reports)}"
            )

            print(
                f"JSON saved to: {OUTPUT_FILE}"
            )

        finally:

            await browser.close()


if __name__ == "__main__":

    asyncio.run(main())