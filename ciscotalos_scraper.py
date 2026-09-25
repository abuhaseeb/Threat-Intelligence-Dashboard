import asyncio
import json
import os
import re
from datetime import datetime
from urllib.parse import urljoin

from playwright.async_api import async_playwright


# ============================================================
# CONFIGURATION
# ============================================================

BASE_URL = "https://blog.talosintelligence.com/"
NUMBER_OF_REPORTS = 5
OUTPUT_FILE = "output/talos_reports.json"


# ============================================================
# TEXT CLEANING
# ============================================================

def clean_text(text):
    if not text:
        return ""

    text = re.sub(r"\s+", " ", text)
    return text.strip()


def unique_list(items):
    """Remove duplicates while preserving order."""

    result = []

    for item in items:
        item = clean_text(item)

        if item and item not in result:
            result.append(item)

    return result


# ============================================================
# IOC EXTRACTION
# ============================================================

def extract_iocs(text):
    """
    Extract common IOC types from article text.
    """

    if not text:
        return {
            "ipv4": [],
            "ipv6": [],
            "domains": [],
            "urls": [],
            "md5": [],
            "sha1": [],
            "sha256": [],
            "emails": [],
            "cves": [],
            "file_names": []
        }

    # --------------------------------------------------------
    # Remove punctuation around indicators
    # --------------------------------------------------------

    source = text

    # --------------------------------------------------------
    # IPv4
    # --------------------------------------------------------

    ipv4_pattern = (
        r"\b(?:(?:25[0-5]|2[0-4]\d|"
        r"[01]?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
    )

    ipv4 = re.findall(ipv4_pattern, source)

    # --------------------------------------------------------
    # IPv6
    # --------------------------------------------------------

    ipv6_pattern = (
        r"\b(?:"
        r"(?:[0-9a-fA-F]{1,4}:){7}"
        r"[0-9a-fA-F]{1,4}"
        r"|"
        r"(?:[0-9a-fA-F]{1,4}:){1,7}:"
        r"|"
        r"(?:[0-9a-fA-F]{1,4}:){1,6}:"
        r"(?:[0-9a-fA-F]{1,4})"
        r")\b"
    )

    ipv6 = re.findall(ipv6_pattern, source)

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    url_pattern = r"https?://[^\s<>\"]+"

    urls = re.findall(url_pattern, source)

    # Clean trailing punctuation
    urls = [
        url.rstrip(".,;:)]}")
        for url in urls
    ]

    # --------------------------------------------------------
    # Domains
    # --------------------------------------------------------

    domain_pattern = (
        r"\b(?:[a-zA-Z0-9-]+\.)+"
        r"(?:com|net|org|io|ru|cn|co|info|biz|"
        r"xyz|top|site|online|me|cc|dev|app|"
        r"live|pro|shop|tech|cloud)\b"
    )

    domains = re.findall(domain_pattern, source)

    # Remove domains that are part of URLs
    for url in urls:

        try:
            domain = re.sub(
                r"^https?://",
                "",
                url
            ).split("/")[0]

            if domain in domains:
                domains.remove(domain)

        except Exception:
            pass

    # --------------------------------------------------------
    # MD5
    # --------------------------------------------------------

    md5_pattern = r"\b[a-fA-F0-9]{32}\b"

    md5 = re.findall(
        md5_pattern,
        source
    )

    # --------------------------------------------------------
    # SHA1
    # --------------------------------------------------------

    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"

    sha1 = re.findall(
        sha1_pattern,
        source
    )

    # --------------------------------------------------------
    # SHA256
    # --------------------------------------------------------

    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    sha256 = re.findall(
        sha256_pattern,
        source
    )

    # --------------------------------------------------------
    # Email addresses
    # --------------------------------------------------------

    email_pattern = (
        r"\b[A-Za-z0-9._%+-]+@"
        r"[A-Za-z0-9.-]+\."
        r"[A-Za-z]{2,}\b"
    )

    emails = re.findall(
        email_pattern,
        source
    )

    # --------------------------------------------------------
    # CVE
    # --------------------------------------------------------

    cve_pattern = r"\bCVE-\d{4}-\d{4,7}\b"

    cves = re.findall(
        cve_pattern,
        source,
        flags=re.IGNORECASE
    )

    cves = [
        cve.upper()
        for cve in cves
    ]

    # --------------------------------------------------------
    # File names
    # --------------------------------------------------------

    file_pattern = (
        r"\b[A-Za-z0-9_.-]+\."
        r"(?:exe|dll|sys|bin|elf|sh|ps1|bat|cmd|"
        r"vbs|js|jar|zip|rar|7z|msi|apk|deb|rpm)\b"
    )

    file_names = re.findall(
        file_pattern,
        source,
        flags=re.IGNORECASE
    )

    return {
        "ipv4": unique_list(ipv4),
        "ipv6": unique_list(ipv6),
        "domains": unique_list(domains),
        "urls": unique_list(urls),
        "md5": unique_list(md5),
        "sha1": unique_list(sha1),
        "sha256": unique_list(sha256),
        "emails": unique_list(emails),
        "cves": unique_list(cves),
        "file_names": unique_list(file_names)
    }


# ============================================================
# EXTRACT PAGE METADATA
# ============================================================

async def get_meta(page, selector, attribute="content"):

    try:

        element = page.locator(selector).first

        if await element.count() > 0:

            value = await element.get_attribute(
                attribute
            )

            return clean_text(value)

    except Exception:
        pass

    return ""


# ============================================================
# FIND ARTICLE LINKS
# ============================================================

async def find_article_links(page):

    article_links = []

    # --------------------------------------------------------
    # Several possible article selectors
    # --------------------------------------------------------

    selectors = [
        "article a[href]",
        "main a[href]",
        "a[href]"
    ]

    for selector in selectors:

        links = page.locator(selector)

        count = await links.count()

        for i in range(count):

            try:

                href = await links.nth(i).get_attribute(
                    "href"
                )

                if not href:
                    continue

                href = urljoin(
                    BASE_URL,
                    href
                )

                # Only Talos blog URLs
                if not href.startswith(
                    "https://blog.talosintelligence.com/"
                ):
                    continue

                # Ignore homepage
                if href.rstrip("/") == BASE_URL.rstrip("/"):
                    continue

                # Ignore category pages
                ignored = [
                    "/category/",
                    "/author/",
                    "/tag/",
                    "/page/",
                    "/search",
                    "/feed/",
                    "/about/",
                    "/contact/"
                ]

                if any(
                    item in href
                    for item in ignored
                ):
                    continue

                if href not in article_links:
                    article_links.append(href)

            except Exception:
                continue

    return article_links


# ============================================================
# EXTRACT ARTICLE SECTIONS
# ============================================================

async def extract_sections(article_page):

    sections = []

    # --------------------------------------------------------
    # Find article/main content
    # --------------------------------------------------------

    article = article_page.locator(
        "article"
    ).first

    if await article.count() == 0:

        article = article_page.locator(
            "main"
        ).first

    if await article.count() == 0:
        return sections

    # --------------------------------------------------------
    # Get all heading elements
    # --------------------------------------------------------

    headings = article.locator(
        "h2, h3, h4"
    )

    heading_count = await headings.count()

    # --------------------------------------------------------
    # If no headings, save entire article
    # --------------------------------------------------------

    if heading_count == 0:

        paragraphs = article.locator(
            "p"
        )

        text_parts = []

        for i in range(
            await paragraphs.count()
        ):

            try:

                text = clean_text(
                    await paragraphs.nth(i).inner_text()
                )

                if text:
                    text_parts.append(text)

            except Exception:
                continue

        sections.append({
            "heading": "Article content",
            "level": "body",
            "description": "\n".join(text_parts),
            "paragraphs": text_parts,
            "bullet_points": [],
            "tables": []
        })

        return sections

    # --------------------------------------------------------
    # Process each heading
    # --------------------------------------------------------

    for i in range(heading_count):

        try:

            heading = headings.nth(i)

            heading_text = clean_text(
                await heading.inner_text()
            )

            if not heading_text:
                continue

            tag_name = await heading.evaluate(
                "(el) => el.tagName.toLowerCase()"
            )

            # ------------------------------------------------
            # Collect content until next heading
            # ------------------------------------------------

            content = await heading.evaluate(
                """
                (heading) => {

                    const result = [];

                    let current = heading.nextElementSibling;

                    while (current) {

                        if (
                            current.matches(
                                "h2, h3, h4"
                            )
                        ) {
                            break;
                        }

                        result.push(
                            current.outerHTML
                        );

                        current =
                            current.nextElementSibling;
                    }

                    return result.join("");
                }
                """
            )

            # ------------------------------------------------
            # Parse temporary section HTML
            # ------------------------------------------------

            temp = await article_page.evaluate(
                """
                (html) => {

                    const div =
                        document.createElement("div");

                    div.innerHTML = html;

                    return {
                        text: div.innerText || "",
                        html: div.innerHTML || ""
                    };
                }
                """,
                content
            )

            section_text = clean_text(
                temp["text"]
            )

            # ------------------------------------------------
            # Paragraphs
            # ------------------------------------------------

            paragraphs = await article_page.evaluate(
                """
                (html) => {

                    const div =
                        document.createElement("div");

                    div.innerHTML = html;

                    return Array.from(
                        div.querySelectorAll("p")
                    )
                    .map(p => p.innerText.trim())
                    .filter(Boolean);
                }
                """,
                content
            )

            # ------------------------------------------------
            # Bullet points
            # ------------------------------------------------

            bullet_points = await article_page.evaluate(
                """
                (html) => {

                    const div =
                        document.createElement("div");

                    div.innerHTML = html;

                    return Array.from(
                        div.querySelectorAll(
                            "li"
                        )
                    )
                    .map(li => li.innerText.trim())
                    .filter(Boolean);
                }
                """,
                content
            )

            # ------------------------------------------------
            # Tables
            # ------------------------------------------------

            tables = await article_page.evaluate(
                """
                (html) => {

                    const div =
                        document.createElement("div");

                    div.innerHTML = html;

                    return Array.from(
                        div.querySelectorAll(
                            "table"
                        )
                    ).map(table => {

                        const rows =
                            Array.from(
                                table.querySelectorAll("tr")
                            );

                        return rows.map(row => {

                            return Array.from(
                                row.querySelectorAll(
                                    "th, td"
                                )
                            ).map(cell =>
                                cell.innerText.trim()
                            );

                        });

                    });
                }
                """,
                content
            )

            sections.append({
                "heading": heading_text,
                "level": tag_name,
                "description": section_text,
                "paragraphs": paragraphs,
                "bullet_points": bullet_points,
                "tables": tables
            })

        except Exception as e:

            print(
                f"Section extraction error: {e}"
            )

    return sections


# ============================================================
# EXTRACT IMAGES
# ============================================================

async def extract_images(article_page):

    images = []

    image_elements = article_page.locator(
        "article img, main img"
    )

    count = await image_elements.count()

    for i in range(count):

        try:

            img = image_elements.nth(i)

            src = await img.get_attribute(
                "src"
            )

            if not src:
                src = await img.get_attribute(
                    "data-src"
                )

            if src:
                src = urljoin(
                    BASE_URL,
                    src
                )

            alt = await img.get_attribute(
                "alt"
            )

            images.append({
                "url": src or "",
                "alt": clean_text(alt)
            })

        except Exception:
            continue

    return images


# ============================================================
# EXTRACT LINKS
# ============================================================

async def extract_links(article_page):

    links_data = []

    links = article_page.locator(
        "article a[href], main a[href]"
    )

    count = await links.count()

    for i in range(count):

        try:

            link = links.nth(i)

            href = await link.get_attribute(
                "href"
            )

            text = clean_text(
                await link.inner_text()
            )

            if href:
                href = urljoin(
                    BASE_URL,
                    href
                )

                links_data.append({
                    "text": text,
                    "url": href
                })

        except Exception:
            continue

    return links_data


# ============================================================
# EXTRACT SINGLE ARTICLE
# ============================================================

async def extract_article(context, article_url):

    print(
        f"\nOpening article:\n{article_url}"
    )

    page = await context.new_page()

    try:

        await page.goto(
            article_url,
            wait_until="domcontentloaded",
            timeout=60000
        )

        # Allow dynamic content to render
        await page.wait_for_timeout(
            2000
        )

        # ----------------------------------------------------
        # TITLE
        # ----------------------------------------------------

        title = ""

        title_selectors = [
            "article h1",
            "main h1",
            "h1"
        ]

        for selector in title_selectors:

            element = page.locator(
                selector
            ).first

            if await element.count() > 0:

                title = clean_text(
                    await element.inner_text()
                )

                if title:
                    break

        # ----------------------------------------------------
        # AUTHOR
        # ----------------------------------------------------

        author = ""

        author_patterns = [
            '[class*="author"]',
            '[class*="Author"]',
            'a[href*="/author/"]'
        ]

        for selector in author_patterns:

            elements = page.locator(
                selector
            )

            count = await elements.count()

            for i in range(
                min(count, 20)
            ):

                try:

                    text = clean_text(
                        await elements.nth(i).inner_text()
                    )

                    if re.search(
                        r"\bBy\s+",
                        text,
                        re.IGNORECASE
                    ):

                        match = re.search(
                            r"\bBy\s+(.+?)(?:\n|$)",
                            text,
                            re.IGNORECASE
                        )

                        if match:

                            author = clean_text(
                                match.group(1)
                            )

                            break

                    # If it is an author link
                    if "/author/" in (
                        await elements.nth(i).get_attribute(
                            "href"
                        ) or ""
                    ):

                        if text:
                            author = text
                            break

                except Exception:
                    continue

            if author:
                break

        # ----------------------------------------------------
        # DATE
        # ----------------------------------------------------

        date = ""

        time_element = page.locator(
            "time"
        ).first

        if await time_element.count() > 0:

            date = clean_text(
                await time_element.inner_text()
            )

            if not date:

                date = clean_text(
                    await time_element.get_attribute(
                        "datetime"
                    )
                )

        # Fallback date pattern
        if not date:

            body_text = clean_text(
                await page.locator(
                    "body"
                ).inner_text()
            )

            date_pattern = (
                r"(January|February|March|April|May|June|"
                r"July|August|September|October|November|"
                r"December)\s+\d{1,2},\s+\d{4}"
            )

            match = re.search(
                date_pattern,
                body_text
            )

            if match:
                date = match.group(0)

        # ----------------------------------------------------
        # META DESCRIPTION
        # ----------------------------------------------------

        meta_description = await get_meta(
            page,
            'meta[name="description"]'
        )

        # ----------------------------------------------------
        # OPEN GRAPH DESCRIPTION
        # ----------------------------------------------------

        og_description = await get_meta(
            page,
            'meta[property="og:description"]'
        )

        description = (
            meta_description
            or og_description
        )

        # ----------------------------------------------------
        # CATEGORIES
        # ----------------------------------------------------

        categories = []

        category_selectors = [
            'a[href*="/category/"]',
            '[class*="category"]',
            '[class*="Category"]'
        ]

        for selector in category_selectors:

            elements = page.locator(
                selector
            )

            count = await elements.count()

            for i in range(count):

                try:

                    text = clean_text(
                        await elements.nth(i).inner_text()
                    )

                    if (
                        text
                        and len(text) < 100
                    ):
                        categories.append(
                            text
                        )

                except Exception:
                    continue

        categories = unique_list(
            categories
        )

        # ----------------------------------------------------
        # TAGS
        # ----------------------------------------------------

        tags = []

        tag_selectors = [
            'a[href*="/tag/"]',
            '[class*="tag"]',
            '[class*="Tag"]'
        ]

        for selector in tag_selectors:

            elements = page.locator(
                selector
            )

            count = await elements.count()

            for i in range(count):

                try:

                    text = clean_text(
                        await elements.nth(i).inner_text()
                    )

                    if text:
                        tags.append(text)

                except Exception:
                    continue

        tags = unique_list(tags)

        # ----------------------------------------------------
        # COMPLETE ARTICLE TEXT
        # ----------------------------------------------------

        article_locator = page.locator(
            "article"
        ).first

        if await article_locator.count() == 0:

            article_locator = page.locator(
                "main"
            ).first

        complete_text = ""

        if await article_locator.count() > 0:

            complete_text = clean_text(
                await article_locator.inner_text()
            )

        # ----------------------------------------------------
        # SECTIONS
        # ----------------------------------------------------

        sections = await extract_sections(
            page
        )

        # ----------------------------------------------------
        # IMAGES
        # ----------------------------------------------------

        images = await extract_images(
            page
        )

        # ----------------------------------------------------
        # LINKS
        # ----------------------------------------------------

        links = await extract_links(
            page
        )

        # ----------------------------------------------------
        # IOC EXTRACTION
        # ----------------------------------------------------

        iocs = extract_iocs(
            complete_text
        )

        # ----------------------------------------------------
        # IOC SECTIONS
        # ----------------------------------------------------

        ioc_sections = []

        for section in sections:

            heading = section.get(
                "heading",
                ""
            )

            heading_lower = heading.lower()

            if (
                "ioc" in heading_lower
                or "indicator" in heading_lower
                or "indicators of compromise"
                in heading_lower
                or "observables" in heading_lower
            ):

                ioc_sections.append(
                    section
                )

        # ----------------------------------------------------
        # RETURN COMPLETE ARTICLE
        # ----------------------------------------------------

        article = {
            "author": author,
            "date": date,
            "title": title,
            "description": description,
            "url": article_url,

            "categories": categories,
            "tags": tags,

            "sections": sections,

            "ioc_sections": ioc_sections,

            "iocs": iocs,

            "images": images,

            "links": links,

            "complete_blog_details": {
                "complete_text": complete_text,
                "section_count": len(
                    sections
                ),
                "image_count": len(
                    images
                ),
                "link_count": len(
                    links
                )
            }
        }

        return article

    except Exception as e:

        print(
            f"ERROR extracting article: {e}"
        )

        return None

    finally:

        await page.close()


# ============================================================
# MAIN SCRAPER
# ============================================================

async def scrape_talos():

    print("=" * 70)
    print("CISCO TALOS INTELLIGENCE BLOG SCRAPER")
    print("=" * 70)

    async with async_playwright() as p:

        # ----------------------------------------------------
        # START BROWSER
        # ----------------------------------------------------

        browser = await p.chromium.launch(
            headless=True
        )

        context = await browser.new_context(
            viewport={
                "width": 1440,
                "height": 1000
            },

            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/151.0.0.0 Safari/537.36"
            )
        )

        page = await context.new_page()

        # ----------------------------------------------------
        # OPEN BLOG
        # ----------------------------------------------------

        print(
            f"\nOpening: {BASE_URL}"
        )

        await page.goto(
            BASE_URL,
            wait_until="domcontentloaded",
            timeout=60000
        )

        await page.wait_for_timeout(
            3000
        )

        print(
            "Talos blog loaded."
        )

        # ----------------------------------------------------
        # FIND ARTICLE LINKS
        # ----------------------------------------------------

        article_links = await find_article_links(
            page
        )

        print(
            f"Candidate article URLs found: "
            f"{len(article_links)}"
        )

        # ----------------------------------------------------
        # SCRAPE ARTICLES
        # ----------------------------------------------------

        reports = []

        for article_url in article_links:

            if len(reports) >= NUMBER_OF_REPORTS:
                break

            article = await extract_article(
                context,
                article_url
            )

            if not article:
                continue

            if not article.get("title"):
                continue

            reports.append(
                article
            )

            print(
                f"\nCollected report "
                f"{len(reports)}/{NUMBER_OF_REPORTS}"
            )

            print(
                f"Title: {article['title']}"
            )

            print(
                f"Author: {article['author']}"
            )

            print(
                f"Date: {article['date']}"
            )

            print(
                f"Sections: "
                f"{len(article['sections'])}"
            )

            print(
                f"IOC IPv4: "
                f"{len(article['iocs']['ipv4'])}"
            )

            print(
                f"IOC domains: "
                f"{len(article['iocs']['domains'])}"
            )

            print(
                f"IOC hashes: "
                f"{len(article['iocs']['sha256']) + len(article['iocs']['sha1']) + len(article['iocs']['md5'])}"
            )

        # ----------------------------------------------------
        # SORT BY DATE
        # ----------------------------------------------------

        def date_sort_key(report):

            date_text = report.get(
                "date",
                ""
            )

            try:

                return datetime.strptime(
                    date_text,
                    "%A, %B %d, %Y %H:%M"
                )

            except Exception:
                pass

            try:

                return datetime.strptime(
                    date_text,
                    "%B %d, %Y"
                )

            except Exception:
                return datetime.min

        reports.sort(
            key=date_sort_key,
            reverse=True
        )

        # Make sure only latest 5 remain
        reports = reports[
            :NUMBER_OF_REPORTS
        ]

        # ----------------------------------------------------
        # CREATE OUTPUT DIRECTORY
        # ----------------------------------------------------

        os.makedirs(
            os.path.dirname(
                OUTPUT_FILE
            ),
            exist_ok=True
        )

        # ----------------------------------------------------
        # CREATE FINAL JSON
        # ----------------------------------------------------

        output = {
            "source": BASE_URL,

            "scraped_at": datetime.now().isoformat(),

            "number_of_reports": len(
                reports
            ),

            "reports": reports
        }

        # ----------------------------------------------------
        # SAVE JSON
        # ----------------------------------------------------

        with open(
            OUTPUT_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                output,
                file,
                indent=4,
                ensure_ascii=False
            )

        # ----------------------------------------------------
        # CLOSE
        # ----------------------------------------------------

        await browser.close()

        print("\n" + "=" * 70)
        print("SCRAPING COMPLETED")
        print("=" * 70)

        print(
            f"Reports scraped: {len(reports)}"
        )

        print(
            f"Output file: {OUTPUT_FILE}"
        )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    asyncio.run(
        scrape_talos()
    )