import asyncio
import json
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError


# ============================================================
# CONFIGURATION
# ============================================================

RESOURCE_URL = (
    "https://www.paloaltonetworks.com/resources"
    "?q=*%3A*"
    "&_charset_=UTF-8"
    "&fq=PRODUCTS0_DFACET%3Apan%253Aresource-center%252Fproducts0%252Funit42-managed-detection-and-response"
    "&fq=RC_TYPE_DFACET%3Apan%253Aresource-center%252Frc-type%252Fresearch"
)

NUMBER_OF_REPORTS = 5

OUTPUT_FILE = "palo_alto_unit42_latest_5_reports.json"

BASE_URL = "https://www.paloaltonetworks.com"


# ============================================================
# TEXT CLEANING
# ============================================================

def clean_text(text):
    if not text:
        return ""

    text = text.replace("\xa0", " ")

    text = re.sub(r"\r\n?", "\n", text)

    # Clean spaces but preserve newlines
    text = re.sub(r"[ \t]+", " ", text)

    # Remove excessive blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


def normalize_url(url):
    if not url:
        return ""

    return urljoin(BASE_URL, url)


def unique_list(values):
    seen = set()
    result = []

    for value in values:
        if not value:
            continue

        value = value.strip()

        if value and value not in seen:
            seen.add(value)
            result.append(value)

    return result


# ============================================================
# DATE PARSING
# ============================================================

def parse_date(date_text):
    """
    Convert common Palo Alto date formats to ISO format.
    """

    if not date_text:
        return None

    date_text = clean_text(date_text)

    formats = [
        "%B %d, %Y",
        "%b %d, %Y",
        "%B %d %Y",
        "%b %d %Y",
        "%m/%d/%Y",
        "%Y-%m-%d",
        "%d %B %Y",
        "%d %b %Y",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(date_text, fmt)
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            pass

    # Search date inside larger text
    patterns = [
        r"(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+\d{4}",
        r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},\s+\d{4}",
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            date_text,
            flags=re.IGNORECASE
        )

        if match:

            extracted = match.group(0)

            for fmt in formats:

                try:
                    dt = datetime.strptime(
                        extracted,
                        fmt
                    )

                    return dt.strftime("%Y-%m-%d")

                except ValueError:
                    pass

    return None


# ============================================================
# IOC EXTRACTION
# ============================================================

def extract_iocs(text):
    """
    Extract common cyber threat intelligence indicators.
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
            "cves": [],
            "mitre_attack": [],
            "emails": [],
            "file_paths": [],
            "registry_keys": []
        }

    # --------------------------------------------------------
    # IPv4
    # --------------------------------------------------------

    ipv4_pattern = r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"

    ipv4 = re.findall(
        ipv4_pattern,
        text
    )

    # Remove obvious version/date-like false positives
    ipv4 = [
        ip for ip in ipv4
        if not ip.startswith(("0.", "127.", "255."))
    ]

    # --------------------------------------------------------
    # IPv6
    # --------------------------------------------------------

    ipv6_pattern = (
        r"\b(?:"
        r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
        r"(?:[0-9a-fA-F]{1,4}:){1,6}:"
        r"[0-9a-fA-F]{1,4}"
        r")\b"
    )

    ipv6 = re.findall(
        ipv6_pattern,
        text
    )

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    url_pattern = r"https?://[^\s<>\[\]\"']+"

    urls = re.findall(
        url_pattern,
        text,
        flags=re.IGNORECASE
    )

    # Remove trailing punctuation
    urls = [
        url.rstrip(".,;:)]}")
        for url in urls
    ]

    # --------------------------------------------------------
    # Domains
    # --------------------------------------------------------

    domain_pattern = (
        r"\b(?:[a-zA-Z0-9-]+\.)+"
        r"(?:com|net|org|io|co|biz|info|xyz|"
        r"ru|cn|uk|de|fr|site|online|me|"
        r"gov|mil|edu|pk)\b"
    )

    domains = re.findall(
        domain_pattern,
        text,
        flags=re.IGNORECASE
    )

    # Don't duplicate domains already contained in URLs
    url_domains = []

    for url in urls:

        try:
            hostname = urlparse(url).hostname

            if hostname:
                url_domains.append(
                    hostname.lower()
                )

        except Exception:
            pass

    domains = [
        domain for domain in domains
        if domain.lower() not in url_domains
    ]

    # --------------------------------------------------------
    # MD5
    # --------------------------------------------------------

    md5_pattern = r"\b[a-fA-F0-9]{32}\b"

    md5 = re.findall(
        md5_pattern,
        text
    )

    # --------------------------------------------------------
    # SHA1
    # --------------------------------------------------------

    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"

    sha1 = re.findall(
        sha1_pattern,
        text
    )

    # --------------------------------------------------------
    # SHA256
    # --------------------------------------------------------

    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    sha256 = re.findall(
        sha256_pattern,
        text
    )

    # --------------------------------------------------------
    # CVE
    # --------------------------------------------------------

    cve_pattern = r"\bCVE-\d{4}-\d{4,7}\b"

    cves = re.findall(
        cve_pattern,
        text,
        flags=re.IGNORECASE
    )

    cves = [
        cve.upper()
        for cve in cves
    ]

    # --------------------------------------------------------
    # MITRE ATT&CK
    # --------------------------------------------------------

    mitre_pattern = r"\bT\d{4}(?:\.\d{3})?\b"

    mitre = re.findall(
        mitre_pattern,
        text,
        flags=re.IGNORECASE
    )

    mitre = [
        item.upper()
        for item in mitre
    ]

    # --------------------------------------------------------
    # EMAILS
    # --------------------------------------------------------

    email_pattern = (
        r"\b[A-Za-z0-9._%+-]+@"
        r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )

    emails = re.findall(
        email_pattern,
        text
    )

    # --------------------------------------------------------
    # Windows file paths
    # --------------------------------------------------------

    file_path_pattern = (
        r"\b[A-Za-z]:\\"
        r"(?:[^\\/:*?\"<>|\r\n]+\\)*"
        r"[^\\/:*?\"<>|\r\n]*"
    )

    file_paths = re.findall(
        file_path_pattern,
        text
    )

    # --------------------------------------------------------
    # Registry keys
    # --------------------------------------------------------

    registry_pattern = (
        r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC)\\"
        r"[A-Za-z0-9_\\\-\s\.]+"
    )

    registry_keys = re.findall(
        registry_pattern,
        text,
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
        "cves": unique_list(cves),
        "mitre_attack": unique_list(mitre),
        "emails": unique_list(emails),
        "file_paths": unique_list(file_paths),
        "registry_keys": unique_list(registry_keys)
    }


# ============================================================
# DISCOVER RESEARCH REPORTS
# ============================================================

async def discover_research_reports(page):

    print("\n[+] Loading Resource Center...")

    try:
        await page.goto(
            RESOURCE_URL,
            wait_until="domcontentloaded",
            timeout=60000
        )
    except Exception as e:
        print(f"[!] Initial navigation warning: {e}")

    try:
        await page.wait_for_load_state(
            "networkidle",
            timeout=20000
        )
    except PlaywrightTimeoutError:
        print(
            "[!] Network idle timeout. "
            "Continuing..."
        )

    await page.wait_for_timeout(5000)

    # --------------------------------------------------------
    # Scroll through resource listing
    # --------------------------------------------------------

    print("[+] Loading resource cards...")

    previous_height = 0

    for i in range(12):

        current_height = await page.evaluate(
            "document.documentElement.scrollHeight"
        )

        if current_height == previous_height:
            break

        previous_height = current_height

        await page.evaluate(
            "window.scrollTo(0, document.documentElement.scrollHeight)"
        )

        await page.wait_for_timeout(1200)

    await page.evaluate(
        "window.scrollTo(0, 0)"
    )

    await page.wait_for_timeout(1000)

    # --------------------------------------------------------
    # Extract all anchors
    # --------------------------------------------------------

    anchors = await page.locator(
        "a[href]"
    ).evaluate_all(
        """
        elements => elements.map(a => ({
            href: a.href,
            text: a.innerText || a.textContent || ""
        }))
        """
    )

    print(
        f"[+] Found {len(anchors)} links on resource page."
    )

    # --------------------------------------------------------
    # Find research report candidates
    # --------------------------------------------------------

    candidates = []

    for anchor in anchors:

        href = normalize_url(
            anchor.get("href", "")
        )

        text = clean_text(
            anchor.get("text", "")
        )

        if not href:
            continue

        if "paloaltonetworks.com" not in href:
            continue

        # Exclude obvious navigation
        if href.rstrip("/") == BASE_URL:
            continue

        candidates.append({
            "url": href.split("#")[0].rstrip("/"),
            "anchor_text": text
        })

    # --------------------------------------------------------
    # Deduplicate
    # --------------------------------------------------------

    unique_candidates = {}

    for candidate in candidates:

        url = candidate["url"]

        if url not in unique_candidates:
            unique_candidates[url] = candidate

    candidates = list(
        unique_candidates.values()
    )

    print(
        f"[+] Candidate resource links: "
        f"{len(candidates)}"
    )

    # --------------------------------------------------------
    # Inspect candidate cards
    #
    # We visit candidate resource pages to determine whether
    # they are actually Research Reports.
    # --------------------------------------------------------

    research_reports = []

    checked = 0

    for candidate in candidates:

        if len(research_reports) >= 30:
            break

        url = candidate["url"]

        # Skip obvious non-resource URLs
        if "/resources/" not in url.lower():
            continue

        checked += 1

        try:

            # Open candidate in a new tab
            report_page = await page.context.new_page()

            await report_page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=45000
            )

            try:
                await report_page.wait_for_load_state(
                    "networkidle",
                    timeout=10000
                )
            except:
                pass

            await report_page.wait_for_timeout(1500)

            page_text = clean_text(
                await report_page.locator(
                    "body"
                ).inner_text()
            )

            page_title = clean_text(
                await report_page.title()
            )

            # ------------------------------------------------
            # Determine resource type
            # ------------------------------------------------

            combined = (
                page_title
                + "\n"
                + page_text[:5000]
            ).lower()

            # Must be explicitly a research report
            if "research reports" not in combined:
                await report_page.close()
                continue

            # Exclude known other resource types
            excluded_types = [
                "whitepaper",
                "webinar",
                "datasheet",
                "case study",
                "solution brief",
                "ebook",
                "e-book",
                "blog"
            ]

            # Only reject if another type appears prominently
            # before the research report designation.
            first_research = combined.find(
                "research reports"
            )

            first_excluded = []

            for item in excluded_types:

                position = combined.find(item)

                if position != -1:
                    first_excluded.append(
                        position
                    )

            if first_excluded:

                earliest_excluded = min(
                    first_excluded
                )

                if earliest_excluded < first_research:
                    await report_page.close()
                    continue

            # ------------------------------------------------
            # Extract date
            # ------------------------------------------------

            date_candidates = []

            # time elements
            time_values = await report_page.locator(
                "time"
            ).all_inner_texts()

            date_candidates.extend(
                time_values
            )

            # Textual date patterns
            date_matches = re.findall(
                r"(?:January|February|March|April|May|June|July|"
                r"August|September|October|November|December)"
                r"\s+\d{1,2},\s+\d{4}",
                page_text,
                flags=re.IGNORECASE
            )

            date_candidates.extend(
                date_matches
            )

            publication_date = None

            for value in date_candidates:

                parsed = parse_date(value)

                if parsed:
                    publication_date = parsed
                    break

            # ------------------------------------------------
            # Extract title
            # ------------------------------------------------

            title = ""

            h1 = report_page.locator("h1")

            if await h1.count() > 0:

                title = clean_text(
                    await h1.first.inner_text()
                )

            if not title:

                title = page_title

            # ------------------------------------------------
            # Description
            # ------------------------------------------------

            description = ""

            meta_desc = report_page.locator(
                'meta[name="description"]'
            )

            if await meta_desc.count() > 0:

                description = clean_text(
                    await meta_desc.first.get_attribute(
                        "content"
                    ) or ""
                )

            research_reports.append({
                "title": title,
                "url": url,
                "publication_date": publication_date,
                "description": description
            })

            print(
                f"[RESEARCH REPORT] "
                f"{publication_date or 'Unknown date'} | "
                f"{title[:100]}"
            )

            await report_page.close()

        except Exception as e:

            print(
                f"[!] Candidate failed: {url}"
            )
            print(
                f"    Reason: {e}"
            )

            try:
                await report_page.close()
            except:
                pass

    print(
        f"\n[+] Research reports discovered: "
        f"{len(research_reports)}"
    )

    # --------------------------------------------------------
    # Deduplicate reports by URL
    # --------------------------------------------------------

    unique_reports = {}

    for report in research_reports:

        unique_reports[
            report["url"]
        ] = report

    research_reports = list(
        unique_reports.values()
    )

    # --------------------------------------------------------
    # Sort newest first
    # --------------------------------------------------------

    research_reports.sort(
        key=lambda x: (
            x["publication_date"] or "0000-00-00"
        ),
        reverse=True
    )

    print("\n[+] Research reports sorted newest first:")

    for i, report in enumerate(
        research_reports[:NUMBER_OF_REPORTS],
        start=1
    ):

        print(
            f"{i}. "
            f"{report['publication_date']} - "
            f"{report['title']}"
        )

    return research_reports[:NUMBER_OF_REPORTS]


# ============================================================
# EXTRACT COMPLETE REPORT
# ============================================================

async def scrape_report(context, report_info, number):

    url = report_info["url"]

    print("\n" + "=" * 80)
    print(
        f"[+] Scraping report {number}/{NUMBER_OF_REPORTS}"
    )
    print(
        f"[+] {url}"
    )

    page = await context.new_page()

    try:

        await page.goto(
            url,
            wait_until="domcontentloaded",
            timeout=60000
        )

        try:

            await page.wait_for_load_state(
                "networkidle",
                timeout=20000
            )

        except PlaywrightTimeoutError:
            pass

        await page.wait_for_timeout(3000)

        # ----------------------------------------------------
        # Scroll entire page
        # ----------------------------------------------------

        previous_height = 0

        for _ in range(20):

            current_height = await page.evaluate(
                "document.documentElement.scrollHeight"
            )

            if current_height == previous_height:
                break

            previous_height = current_height

            await page.evaluate(
                "window.scrollTo(0, document.documentElement.scrollHeight)"
            )

            await page.wait_for_timeout(700)

        await page.evaluate(
            "window.scrollTo(0, 0)"
        )

        await page.wait_for_timeout(1000)

        # ----------------------------------------------------
        # PAGE TITLE
        # ----------------------------------------------------

        page_title = clean_text(
            await page.title()
        )

        # ----------------------------------------------------
        # H1
        # ----------------------------------------------------

        title = ""

        h1 = page.locator("h1")

        if await h1.count() > 0:

            title = clean_text(
                await h1.first.inner_text()
            )

        if not title:
            title = report_info["title"]

        # ----------------------------------------------------
        # META DESCRIPTION
        # ----------------------------------------------------

        description = ""

        meta_description = page.locator(
            'meta[name="description"]'
        )

        if await meta_description.count() > 0:

            description = clean_text(
                await meta_description.first.get_attribute(
                    "content"
                ) or ""
            )

        if not description:
            description = report_info.get(
                "description",
                ""
            )

        # ----------------------------------------------------
        # CANONICAL URL
        # ----------------------------------------------------

        canonical_url = url

        canonical = page.locator(
            'link[rel="canonical"]'
        )

        if await canonical.count() > 0:

            canonical_url = normalize_url(
                await canonical.first.get_attribute(
                    "href"
                ) or url
            )

        # ----------------------------------------------------
        # DATE
        # ----------------------------------------------------

        publication_date = (
            report_info.get(
                "publication_date"
            )
        )

        # Search page for date if missing
        if not publication_date:

            body_text_for_date = clean_text(
                await page.locator(
                    "body"
                ).inner_text()
            )

            date_matches = re.findall(
                r"(?:January|February|March|April|May|June|July|"
                r"August|September|October|November|December)"
                r"\s+\d{1,2},\s+\d{4}",
                body_text_for_date,
                flags=re.IGNORECASE
            )

            for date_value in date_matches:

                parsed = parse_date(
                    date_value
                )

                if parsed:
                    publication_date = parsed
                    break

        # ----------------------------------------------------
        # AUTHORS
        # ----------------------------------------------------

        authors = []

        # Common author selectors
        author_selectors = [
            '[rel="author"]',
            ".author",
            ".authors",
            ".author-name",
            '[class*="author"]'
        ]

        for selector in author_selectors:

            locator = page.locator(
                selector
            )

            if await locator.count() == 0:
                continue

            try:

                values = await locator.all_inner_texts()

                for value in values:

                    value = clean_text(value)

                    if (
                        value
                        and len(value) < 150
                    ):
                        authors.append(value)

            except:
                pass

        # ----------------------------------------------------
        # JSON-LD
        # ----------------------------------------------------

        json_ld = []

        ld_scripts = await page.locator(
            'script[type="application/ld+json"]'
        ).all_inner_texts()

        for script in ld_scripts:

            script = script.strip()

            if not script:
                continue

            try:

                data = json.loads(script)

                if isinstance(data, list):
                    json_ld.extend(data)
                else:
                    json_ld.append(data)

            except Exception:
                pass

        # Extract authors from JSON-LD
        for item in json_ld:

            if not isinstance(item, dict):
                continue

            author_data = item.get(
                "author"
            )

            if isinstance(author_data, dict):

                name = author_data.get(
                    "name"
                )

                if name:
                    authors.append(
                        clean_text(name)
                    )

            elif isinstance(
                author_data,
                list
            ):

                for author in author_data:

                    if isinstance(
                        author,
                        dict
                    ):

                        name = author.get(
                            "name"
                        )

                        if name:
                            authors.append(
                                clean_text(name)
                            )

        authors = unique_list(authors)

        # ----------------------------------------------------
        # HEADINGS / SECTIONS
        # ----------------------------------------------------

        headings = await page.locator(
            "h1, h2, h3, h4, h5, h6"
        ).evaluate_all(
            """
            elements => elements.map(el => ({
                level: el.tagName.toLowerCase(),
                text: (el.innerText || el.textContent || "").trim()
            })).filter(x => x.text)
            """
        )

        cleaned_headings = []

        for heading in headings:

            cleaned_headings.append({
                "level": heading["level"],
                "text": clean_text(
                    heading["text"]
                )
            })

        # ----------------------------------------------------
        # SECTIONS
        # ----------------------------------------------------
        #
        # Each heading is associated with the text until the
        # next heading.
        # ----------------------------------------------------

        sections = await page.locator(
            "h1, h2, h3, h4, h5, h6"
        ).evaluate_all(
            """
            headings => {

                function clean(text) {
                    return text
                        .replace(/\\s+/g, " ")
                        .trim();
                }

                const output = [];

                headings.forEach((heading, index) => {

                    const section = {
                        heading_level:
                            heading.tagName.toLowerCase(),

                        heading:
                            clean(
                                heading.innerText ||
                                heading.textContent ||
                                ""
                            ),

                        content: []
                    };

                    let current = heading.nextElementSibling;

                    while (
                        current &&
                        !/^H[1-6]$/.test(
                            current.tagName
                        )
                    ) {

                        const text =
                            current.innerText ||
                            current.textContent ||
                            "";

                        const cleaned =
                            clean(text);

                        if (cleaned) {
                            section.content.push(
                                cleaned
                            );
                        }

                        current =
                            current.nextElementSibling;
                    }

                    section.content =
                        section.content.join("\\n\\n");

                    output.push(section);
                });

                return output;
            }
            """
        )

        # ----------------------------------------------------
        # MAIN CONTENT
        # ----------------------------------------------------

        main_content = ""

        selectors = [
            "main",
            "[role='main']",
            "article",
            ".resource-content",
            ".page-content",
            ".content"
        ]

        for selector in selectors:

            locator = page.locator(
                selector
            )

            if await locator.count() == 0:
                continue

            try:

                text = clean_text(
                    await locator.first.inner_text()
                )

                if len(text) > len(
                    main_content
                ):
                    main_content = text

            except:
                pass

        # ----------------------------------------------------
        # FULL BODY TEXT
        # ----------------------------------------------------

        full_body_text = clean_text(
            await page.locator(
                "body"
            ).inner_text()
        )

        # ----------------------------------------------------
        # PARAGRAPHS
        # ----------------------------------------------------

        paragraphs = await page.locator(
            "main p, article p, .content p, body p"
        ).evaluate_all(
            """
            elements => elements.map(
                el => (
                    el.innerText ||
                    el.textContent ||
                    ""
                ).trim()
            ).filter(Boolean)
            """
        )

        paragraphs = unique_list(
            [
                clean_text(p)
                for p in paragraphs
            ]
        )

        # ----------------------------------------------------
        # LIST ITEMS
        # ----------------------------------------------------

        list_items = await page.locator(
            "main li, article li, .content li"
        ).evaluate_all(
            """
            elements => elements.map(
                el => (
                    el.innerText ||
                    el.textContent ||
                    ""
                ).trim()
            ).filter(Boolean)
            """
        )

        list_items = unique_list(
            [
                clean_text(item)
                for item in list_items
            ]
        )

        # ----------------------------------------------------
        # LINKS
        # ----------------------------------------------------

        links = await page.locator(
            "a[href]"
        ).evaluate_all(
            """
            elements => elements.map(a => ({
                text: (
                    a.innerText ||
                    a.textContent ||
                    ""
                ).trim(),

                href: a.href
            })).filter(x => x.href)
            """
        )

        clean_links = []

        seen_links = set()

        for link in links:

            href = normalize_url(
                link["href"]
            )

            text = clean_text(
                link["text"]
            )

            key = (
                href,
                text
            )

            if key in seen_links:
                continue

            seen_links.add(key)

            clean_links.append({
                "text": text,
                "url": href
            })

        # ----------------------------------------------------
        # IMAGES
        # ----------------------------------------------------

        images = await page.locator(
            "img"
        ).evaluate_all(
            """
            elements => elements.map(img => ({
                src:
                    img.src ||
                    img.getAttribute("src") ||
                    "",

                alt:
                    img.alt || "",

                title:
                    img.title || ""
            })).filter(x => x.src)
            """
        )

        clean_images = []

        seen_images = set()

        for image in images:

            src = normalize_url(
                image["src"]
            )

            if src in seen_images:
                continue

            seen_images.add(src)

            clean_images.append({
                "url": src,
                "alt": clean_text(
                    image["alt"]
                ),
                "title": clean_text(
                    image["title"]
                )
            })

        # ----------------------------------------------------
        # TABLES
        # ----------------------------------------------------

        tables = []

        table_count = await page.locator(
            "table"
        ).count()

        for table_index in range(
            table_count
        ):

            table = page.locator(
                "table"
            ).nth(table_index)

            rows = await table.locator(
                "tr"
            ).evaluate_all(
                """
                rows => rows.map(row =>
                    Array.from(
                        row.querySelectorAll(
                            "th, td"
                        )
                    ).map(cell =>
                        (
                            cell.innerText ||
                            cell.textContent ||
                            ""
                        ).trim()
                    )
                )
                """
            )

            tables.append({
                "table_number":
                    table_index + 1,
                "rows": rows
            })

        # ----------------------------------------------------
        # IOC EXTRACTION
        # ----------------------------------------------------

        iocs = extract_iocs(
            full_body_text
        )

        # ----------------------------------------------------
        # STRUCTURED DATA
        # ----------------------------------------------------

        # Keep JSON-LD because it can contain additional
        # publication metadata.
        structured_data = json_ld

        # ----------------------------------------------------
        # REPORT TYPE
        # ----------------------------------------------------

        report_type = "Research Reports"

        # ----------------------------------------------------
        # FINAL REPORT OBJECT
        # ----------------------------------------------------

        report = {

            "resource_type":
                report_type,

            "source": {
                "website":
                    "Palo Alto Networks",

                "organization":
                    "Unit 42",

                "resource_center":
                    RESOURCE_URL,

                "url":
                    url,

                "canonical_url":
                    canonical_url
            },

            "metadata": {

                "title":
                    title,

                "page_title":
                    page_title,

                "description":
                    description,

                "publication_date":
                    publication_date,

                "authors":
                    authors,

                "language":
                    "English"
            },

            "content": {

                "full_text":
                    full_body_text,

                "main_content":
                    main_content,

                "paragraphs":
                    paragraphs,

                "headings":
                    cleaned_headings,

                "sections":
                    sections,

                "list_items":
                    list_items,

                "tables":
                    tables
            },

            "threat_intelligence": {

                "iocs":
                    iocs
            },

            "links":
                clean_links,

            "images":
                clean_images,

            "structured_data":
                structured_data
        }

        print(
            f"[+] Title: {title}"
        )

        print(
            f"[+] Date: "
            f"{publication_date}"
        )

        print(
            f"[+] Authors: "
            f"{len(authors)}"
        )

        print(
            f"[+] Sections: "
            f"{len(sections)}"
        )

        print(
            f"[+] Paragraphs: "
            f"{len(paragraphs)}"
        )

        print(
            f"[+] IOCs: "
            f"{sum(len(v) for v in iocs.values())}"
        )

        return report

    except Exception as e:

        print(
            f"[ERROR] Failed to scrape report:"
        )

        print(
            f"        {url}"
        )

        print(
            f"        {e}"
        )

        return None

    finally:

        await page.close()


# ============================================================
# MAIN
# ============================================================

async def main():

    print("=" * 80)
    print("PALO ALTO NETWORKS UNIT 42 RESEARCH REPORT SCRAPER")
    print("=" * 80)

    async with async_playwright() as playwright:

        browser = await playwright.chromium.launch(
            headless=False
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

        # ====================================================
        # STEP 1
        # Find ONLY research reports
        # ====================================================

        latest_reports = (
            await discover_research_reports(
                page
            )
        )

        await page.close()

        if not latest_reports:

            print(
                "\n[ERROR] No research reports found."
            )

            print(
                "Check the website structure or "
                "resource filters."
            )

            await browser.close()
            return

        # ====================================================
        # STEP 2
        # Scrape complete report pages
        # ====================================================

        scraped_reports = []

        for index, report_info in enumerate(
            latest_reports,
            start=1
        ):

            report = await scrape_report(
                context,
                report_info,
                index
            )

            if report:
                scraped_reports.append(
                    report
                )

            await asyncio.sleep(1)

        # ====================================================
        # STEP 3
        # Final JSON
        # ====================================================

        output = {

            "scraper": {

                "name":
                    "Palo Alto Networks Unit 42 "
                    "Research Report Scraper",

                "source":
                    RESOURCE_URL,

                "resource_type":
                    "Research Reports",

                "requested":
                    NUMBER_OF_REPORTS,

                "scraped":
                    len(scraped_reports),

                "scraped_at":
                    datetime.utcnow()
                    .isoformat() + "Z"
            },

            "reports":
                scraped_reports
        }

        # ====================================================
        # STEP 4
        # Save JSON
        # ====================================================

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

        print("\n" + "=" * 80)
        print("SCRAPING COMPLETED")
        print("=" * 80)

        print(
            f"Research reports scraped: "
            f"{len(scraped_reports)}"
        )

        print(
            f"Output file: "
            f"{OUTPUT_FILE}"
        )

        print("=" * 80)

        await browser.close()


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    asyncio.run(main())