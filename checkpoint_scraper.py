import asyncio
import json
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright


BASE_URL = "https://research.checkpoint.com"
PUBLICATIONS_URL = "https://research.checkpoint.com/latest-publications/"
OUTPUT_FILE = "checkpoint_latest_5_reports.json"

NUMBER_OF_REPORTS = 5


# ---------------------------------------------------------
# Utility functions
# ---------------------------------------------------------

def clean_text(text):
    """Clean excessive whitespace while preserving readable text."""
    if not text:
        return ""

    text = text.replace("\xa0", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


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
    Extract common IOC indicators from article text.

    This is intentionally broad because cybersecurity reports
    can contain many different IOC formats.
    """

    if not text:
        return {
            "ipv4_addresses": [],
            "ipv6_addresses": [],
            "domains": [],
            "urls": [],
            "email_addresses": [],
            "md5": [],
            "sha1": [],
            "sha256": [],
            "sha512": [],
            "file_names": [],
            "registry_paths": [],
            "cves": []
        }

    # -----------------------------------------------------
    # IPv4
    # -----------------------------------------------------

    ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    ipv4 = re.findall(ipv4_pattern, text)

    # Remove obviously invalid IPv4 values
    valid_ipv4 = []

    for ip in ipv4:
        try:
            parts = [int(x) for x in ip.split(".")]

            if all(0 <= x <= 255 for x in parts):
                valid_ipv4.append(ip)

        except ValueError:
            pass

    # -----------------------------------------------------
    # IPv6
    # -----------------------------------------------------

    ipv6_pattern = (
        r"\b(?:"
        r"[0-9a-fA-F]{1,4}:){2,7}"
        r"[0-9a-fA-F]{1,4}"
        r"\b"
    )

    ipv6 = re.findall(ipv6_pattern, text)

    # -----------------------------------------------------
    # URLs
    # -----------------------------------------------------

    url_pattern = r"https?://[^\s<>\"]+"

    urls = re.findall(url_pattern, text)

    urls = [
        url.rstrip(".,);]}>'\"")
        for url in urls
    ]

    # -----------------------------------------------------
    # Domains
    # -----------------------------------------------------

    domain_pattern = (
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}\b"
    )

    domains = re.findall(domain_pattern, text)

    # Remove domains that are clearly file extensions
    domains = [
        d for d in domains
        if "." in d
    ]

    # -----------------------------------------------------
    # Email addresses
    # -----------------------------------------------------

    email_pattern = (
        r"\b[A-Za-z0-9._%+-]+@"
        r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )

    emails = re.findall(email_pattern, text)

    # -----------------------------------------------------
    # MD5
    # -----------------------------------------------------

    md5_pattern = r"\b[a-fA-F0-9]{32}\b"

    md5 = re.findall(md5_pattern, text)

    # -----------------------------------------------------
    # SHA1
    # -----------------------------------------------------

    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"

    sha1 = re.findall(sha1_pattern, text)

    # -----------------------------------------------------
    # SHA256
    # -----------------------------------------------------

    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    sha256 = re.findall(sha256_pattern, text)

    # -----------------------------------------------------
    # SHA512
    # -----------------------------------------------------

    sha512_pattern = r"\b[a-fA-F0-9]{128}\b"

    sha512 = re.findall(sha512_pattern, text)

    # -----------------------------------------------------
    # CVE
    # -----------------------------------------------------

    cve_pattern = r"\bCVE-\d{4}-\d{4,7}\b"

    cves = re.findall(
        cve_pattern,
        text,
        flags=re.IGNORECASE
    )

    cves = [x.upper() for x in cves]

    # -----------------------------------------------------
    # Windows registry paths
    # -----------------------------------------------------

    registry_pattern = (
        r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC)"
        r"\\[A-Za-z0-9_\\ .:{}@\-]+\b"
    )

    registry_paths = re.findall(
        registry_pattern,
        text,
        flags=re.IGNORECASE
    )

    # -----------------------------------------------------
    # File names
    # -----------------------------------------------------

    file_pattern = (
        r"\b[A-Za-z0-9_\-\.]{2,100}"
        r"\.(?:exe|dll|sys|dat|bin|ps1|bat|cmd|vbs|js|hta|msi|"
        r"scr|drv|tmp|log|zip|rar|7z)\b"
    )

    file_names = re.findall(
        file_pattern,
        text,
        flags=re.IGNORECASE
    )

    return {
        "ipv4_addresses": unique_list(valid_ipv4),
        "ipv6_addresses": unique_list(ipv6),
        "domains": unique_list(domains),
        "urls": unique_list(urls),
        "email_addresses": unique_list(emails),
        "md5": unique_list(md5),
        "sha1": unique_list(sha1),
        "sha256": unique_list(sha256),
        "sha512": unique_list(sha512),
        "file_names": unique_list(file_names),
        "registry_paths": unique_list(registry_paths),
        "cves": unique_list(cves)
    }


# ---------------------------------------------------------
# Get latest publication links
# ---------------------------------------------------------

async def get_latest_publications(page):

    print("\nOpening:")
    print(PUBLICATIONS_URL)

    await page.goto(
        PUBLICATIONS_URL,
        wait_until="domcontentloaded",
        timeout=60000
    )

    await page.wait_for_timeout(3000)

    # -----------------------------------------------------
    # Find article links.
    #
    # Check Point publication URLs generally contain
    # /2026/, /2025/, etc.
    # -----------------------------------------------------

    links = await page.locator("a[href]").evaluate_all(
        """
        elements => elements.map(a => ({
            href: a.href,
            text: a.innerText.trim()
        }))
        """
    )

    publications = []
    seen = set()

    for item in links:

        href = item.get("href", "")
        text = item.get("text", "").strip()

        if not href:
            continue

        # Only Check Point Research URLs
        if not href.startswith(BASE_URL):
            continue

        parsed = urlparse(href)

        path = parsed.path.rstrip("/")

        # Skip main website pages
        if path in [
            "",
            "/",
            "/latest-publications",
            "/category/threat-research"
        ]:
            continue

        # Check Point research article URLs generally contain
        # a year in their path.
        if not re.search(r"/20\d{2}/", path):
            continue

        # Ignore obvious non-publication pages
        excluded = [
            "/about/",
            "/contact/",
            "/author/",
            "/tag/",
            "/category/"
        ]

        if any(x in path for x in excluded):
            continue

        # Remove query strings/fragments
        clean_url = href.split("#")[0].split("?")[0].rstrip("/")

        if clean_url in seen:
            continue

        seen.add(clean_url)

        publications.append({
            "title_from_listing": clean_text(text),
            "url": clean_url
        })

    print(f"\nFound {len(publications)} candidate publication links.")

    return publications[:NUMBER_OF_REPORTS]


# ---------------------------------------------------------
# Extract article sections
# ---------------------------------------------------------

async def extract_sections(article_page):

    sections = []

    # Most Check Point articles use article/content containers.
    possible_containers = [
        "article",
        ".post-content",
        ".entry-content",
        ".article-content",
        ".single-post-content",
        "main"
    ]

    container = None

    for selector in possible_containers:

        locator = article_page.locator(selector)

        if await locator.count() > 0:

            # Choose the largest matching container
            count = await locator.count()

            best_index = 0
            best_length = 0

            for i in range(count):

                try:
                    text = await locator.nth(i).inner_text()

                    if len(text) > best_length:
                        best_length = len(text)
                        best_index = i

                except Exception:
                    pass

            if best_length > 500:
                container = locator.nth(best_index)
                break

    if container is None:
        return sections

    # -----------------------------------------------------
    # Read H1-H6 headings and their following content.
    # -----------------------------------------------------

    blocks = await container.locator(
        "h1, h2, h3, h4, h5, h6, p, ul, ol, table, blockquote, pre"
    ).evaluate_all(
        """
        elements => elements.map(el => {

            let type = el.tagName.toLowerCase();

            let content = "";

            if (type === "table") {

                const rows = [...el.querySelectorAll("tr")];

                content = rows.map(row => {

                    const cells = [...row.querySelectorAll("th, td")];

                    return cells
                        .map(cell => cell.innerText.trim())
                        .join(" | ");

                }).join("\\n");

            }

            else if (type === "ul" || type === "ol") {

                content = [...el.querySelectorAll(":scope > li")]
                    .map(li => li.innerText.trim())
                    .join("\\n");

            }

            else {

                content = el.innerText.trim();

            }

            return {
                type: type,
                text: content
            };
        })
        """
    )

    current_section = None

    for block in blocks:

        block_type = block["type"]
        text = clean_text(block["text"])

        if not text:
            continue

        if block_type in [
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6"
        ]:

            # Ignore duplicate page title
            if (
                current_section
                and current_section["heading"].lower() == text.lower()
            ):
                continue

            current_section = {
                "heading": text,
                "level": int(block_type[1]),
                "content": []
            }

            sections.append(current_section)

        else:

            if current_section is None:

                current_section = {
                    "heading": "Introduction / Unsectioned Content",
                    "level": 0,
                    "content": []
                }

                sections.append(current_section)

            current_section["content"].append({
                "type": block_type,
                "text": text
            })

    return sections


# ---------------------------------------------------------
# Extract complete article
# ---------------------------------------------------------

async def scrape_article(browser, publication):

    url = publication["url"]

    print("\n" + "=" * 80)
    print("Scraping:")
    print(url)
    print("=" * 80)

    page = await browser.new_page()

    try:

        await page.goto(
            url,
            wait_until="domcontentloaded",
            timeout=60000
        )

        # Give dynamically loaded content time to appear
        await page.wait_for_timeout(2500)

        # -------------------------------------------------
        # Title
        # -------------------------------------------------

        title = ""

        if await page.locator("h1").count() > 0:
            title = await page.locator("h1").first.inner_text()

        title = clean_text(title)

        # -------------------------------------------------
        # Date
        # -------------------------------------------------

        publication_date = ""

        date_selectors = [
            "time",
            ".entry-date",
            ".post-date",
            ".published",
            "[class*='date']"
        ]

        for selector in date_selectors:

            locator = page.locator(selector)

            if await locator.count() > 0:

                for i in range(min(await locator.count(), 5)):

                    try:

                        value = await locator.nth(i).get_attribute("datetime")

                        if value:
                            publication_date = value.strip()
                            break

                        value = await locator.nth(i).inner_text()

                        if value and re.search(
                            r"(January|February|March|April|May|June|July|"
                            r"August|September|October|November|December)",
                            value,
                            re.IGNORECASE
                        ):

                            publication_date = clean_text(value)
                            break

                    except Exception:
                        pass

            if publication_date:
                break

        # -------------------------------------------------
        # Author / Researcher
        # -------------------------------------------------

        author = ""

        author_selectors = [
            "[class*='author']",
            ".author",
            ".post-author",
            ".entry-author"
        ]

        for selector in author_selectors:

            locator = page.locator(selector)

            if await locator.count() > 0:

                for i in range(min(await locator.count(), 10)):

                    try:

                        text = clean_text(
                            await locator.nth(i).inner_text()
                        )

                        if not text:
                            continue

                        # Avoid generic "author" labels
                        if len(text) < 300:

                            if (
                                "research by" in text.lower()
                                or "by " in text.lower()
                                or "author" in text.lower()
                                or len(text.split()) <= 8
                            ):
                                author = text
                                break

                    except Exception:
                        pass

            if author:
                break

        # -------------------------------------------------
        # Look specifically for "Research by"
        # -------------------------------------------------

        research_by = ""

        body_text = clean_text(
            await page.locator("body").inner_text()
        )

        match = re.search(
            r"Research by:\s*(.+?)(?:\n|Abstract|Introduction|$)",
            body_text,
            flags=re.IGNORECASE
        )

        if match:
            research_by = clean_text(match.group(1))

        if research_by:
            author = research_by

        # -------------------------------------------------
        # Meta description
        # -------------------------------------------------

        meta_description = ""

        meta = page.locator(
            'meta[name="description"]'
        )

        if await meta.count() > 0:
            meta_description = (
                await meta.first.get_attribute("content")
                or ""
            )

        meta_description = clean_text(meta_description)

        # -------------------------------------------------
        # Sections
        # -------------------------------------------------

        sections = await extract_sections(page)

        # -------------------------------------------------
        # Extract article text from sections
        # -------------------------------------------------

        complete_parts = []

        for section in sections:

            complete_parts.append(
                section["heading"]
            )

            for content in section["content"]:

                complete_parts.append(
                    content["text"]
                )

        complete_text = "\n\n".join(complete_parts)

        complete_text = clean_text(complete_text)

        # -------------------------------------------------
        # Find Abstract
        # -------------------------------------------------

        description = ""

        for section in sections:

            heading = section["heading"].lower()

            if heading in [
                "abstract",
                "summary",
                "key points",
                "overview"
            ]:

                description = "\n\n".join(
                    item["text"]
                    for item in section["content"]
                )

                description = clean_text(description)

                if description:
                    break

        # If no abstract section exists, use meta description
        if not description:
            description = meta_description

        # -------------------------------------------------
        # Extract links from article
        # -------------------------------------------------

        article_links = []

        try:

            article_links = await page.locator(
                "article a[href], main a[href]"
            ).evaluate_all(
                """
                links => links.map(a => ({
                    text: a.innerText.trim(),
                    url: a.href
                }))
                """
            )

        except Exception:
            article_links = []

        cleaned_links = []

        for link in article_links:

            link_url = link.get("url", "").strip()
            link_text = clean_text(link.get("text", ""))

            if not link_url:
                continue

            cleaned_links.append({
                "text": link_text,
                "url": link_url
            })

        # -------------------------------------------------
        # IOC extraction
        # -------------------------------------------------

        iocs = extract_iocs(complete_text)

        # -------------------------------------------------
        # Images
        # -------------------------------------------------

        images = []

        try:

            images = await page.locator(
                "article img, main img"
            ).evaluate_all(
                """
                imgs => imgs.map(img => ({
                    src: img.src,
                    alt: img.alt || "",
                    title: img.title || ""
                }))
                """
            )

        except Exception:
            images = []

        # Remove duplicate images
        unique_images = []
        seen_images = set()

        for image in images:

            src = image.get("src", "")

            if src and src not in seen_images:

                seen_images.add(src)
                unique_images.append(image)

        # -------------------------------------------------
        # Result
        # -------------------------------------------------

        result = {
            "source": "Check Point Research",

            "title": title,

            "author": author,

            "publication_date": publication_date,

            "url": url,

            "description": description,

            "article_sections": sections,

            "complete_article_text": complete_text,

            "iocs": iocs,

            "article_links": cleaned_links,

            "images": unique_images,

            "scraped_at": datetime.now().isoformat()
        }

        print("Title:", title)
        print("Author:", author)
        print("Date:", publication_date)
        print("Sections:", len(sections))

        total_iocs = sum(
            len(value)
            for value in iocs.values()
        )

        print("IOC indicators:", total_iocs)

        return result

    except Exception as e:

        print("ERROR:", e)

        return {
            "source": "Check Point Research",
            "title": publication.get(
                "title_from_listing",
                ""
            ),
            "url": url,
            "error": str(e)
        }

    finally:

        await page.close()


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

async def main():

    async with async_playwright() as p:

        print("Starting Chromium...")

        browser = await p.chromium.launch(
            headless=True
        )

        context = await browser.new_context(
            viewport={
                "width": 1920,
                "height": 1080
            },

            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/151.0.0.0 Safari/537.36"
            ),

            locale="en-US"
        )

        listing_page = await context.new_page()

        # -------------------------------------------------
        # Get latest five articles
        # -------------------------------------------------

        publications = await get_latest_publications(
            listing_page
        )

        await listing_page.close()

        print("\nLatest publications selected:")

        for index, publication in enumerate(
            publications,
            start=1
        ):

            print(
                f"{index}. "
                f"{publication['title_from_listing']} "
                f"-> {publication['url']}"
            )

        # -------------------------------------------------
        # Scrape each article
        # -------------------------------------------------

        reports = []

        for publication in publications:

            report = await scrape_article(
                context,
                publication
            )

            reports.append(report)

        # -------------------------------------------------
        # Save JSON
        # -------------------------------------------------

        output = {
            "source": PUBLICATIONS_URL,

            "scrape_date": datetime.now().isoformat(),

            "number_of_reports": len(reports),

            "reports": reports
        }

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

        await browser.close()

        print("\n" + "=" * 80)
        print("SCRAPING COMPLETED")
        print("=" * 80)

        print(
            f"Reports scraped: {len(reports)}"
        )

        print(
            f"JSON saved to: {OUTPUT_FILE}"
        )


if __name__ == "__main__":

    asyncio.run(main())