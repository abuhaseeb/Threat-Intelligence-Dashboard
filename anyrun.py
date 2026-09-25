import asyncio
import json
import re
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError


# ============================================================
# CONFIGURATION
# ============================================================

SOURCE_URL = "https://any.run/malware-trends/"
OUTPUT_FILE = "anyrun_malware_trends.json"
TOP_N = 20


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def clean_text(text):
    """Remove extra whitespace."""
    if not text:
        return ""

    return re.sub(r"\s+", " ", text).strip()


def absolute_url(href):
    """Convert relative URL to absolute URL."""
    if not href:
        return ""

    return urljoin(SOURCE_URL, href)


def is_individual_trend_url(url):
    """
    Return True only for URLs like:

        https://any.run/malware-trends/kali365/

    and not:

        https://any.run/malware-trends/
    """

    if not url:
        return False

    parsed = urlparse(url)

    if parsed.netloc not in ("any.run", "www.any.run"):
        return False

    path = parsed.path.rstrip("/")

    if not path.startswith("/malware-trends/"):
        return False

    malware_slug = path[len("/malware-trends/"):]

    if not malware_slug:
        return False

    # Individual trend URL should contain one slug only.
    if "/" in malware_slug:
        return False

    return True


def get_slug(url):
    """Extract malware slug from a trend URL."""

    parsed = urlparse(url)

    parts = [
        part
        for part in parsed.path.split("/")
        if part
    ]

    if len(parts) >= 2:
        if parts[0] == "malware-trends":
            return parts[1]

    return ""


# ============================================================
# GET TOP 20 MALWARE TREND LINKS
# ============================================================

async def get_top_trends(page):
    """
    Scrape the first 20 individual malware trend links.

    We use state='attached' because ANY.RUN contains many
    matching hidden/navigation elements.
    """

    print()
    print("=" * 70)
    print("STEP 1 - OPEN ANY.RUN MALWARE TRENDS")
    print("=" * 70)

    print(f"URL: {SOURCE_URL}")

    await page.goto(
        SOURCE_URL,
        wait_until="domcontentloaded",
        timeout=90000
    )

    # Wait for the links to exist in the DOM.
    try:
        await page.wait_for_selector(
            'a[href*="/malware-trends/"]',
            state="attached",
            timeout=60000
        )
    except PlaywrightTimeoutError:
        print("Warning: trend links were not detected immediately.")

    # Allow JavaScript rendering.
    await page.wait_for_timeout(3000)

    # Get all matching links.
    links = page.locator(
        'a[href*="/malware-trends/"]'
    )

    total_links = await links.count()

    print(f"Matching links found: {total_links}")

    records = []
    seen_urls = set()

    for i in range(total_links):

        link = links.nth(i)

        try:
            href = await link.get_attribute("href")
        except Exception:
            continue

        if not href:
            continue

        url = absolute_url(href)

        # We only want individual malware pages.
        if not is_individual_trend_url(url):
            continue

        # Remove duplicates.
        if url in seen_urls:
            continue

        seen_urls.add(url)

        # Get anchor text.
        try:
            text = clean_text(
                await link.inner_text()
            )
        except Exception:
            text = ""

        # Fallback to slug.
        if not text:
            text = get_slug(url)

        # ANY.RUN trend list contains "Active" / "Inactive"
        # before the malware name in the anchor text.
        text = re.sub(
            r"^(Active|Inactive)\s+",
            "",
            text,
            flags=re.IGNORECASE
        )

        records.append(
            {
                "malware_name": text,
                "trend_url": url
            }
        )

        if len(records) >= TOP_N:
            break

    print(f"Unique malware trends extracted: {len(records)}")

    return records


# ============================================================
# GET MALWARE TYPE AND REPORT/TASK URL
# ============================================================

async def get_trend_details(page, record):
    """
    Open an individual malware trend page.

    Extract:

        - malware name
        - type
        - report/task URL
    """

    trend_url = record["trend_url"]

    print()
    print("-" * 70)
    print(f"Malware: {record['malware_name']}")
    print(f"Trend:   {trend_url}")

    try:
        await page.goto(
            trend_url,
            wait_until="domcontentloaded",
            timeout=90000
        )

    except PlaywrightTimeoutError:
        print("WARNING: page load timed out.")
        print("Continuing with loaded content.")

    except Exception as exc:
        print(f"ERROR opening trend page: {exc}")

        record["type"] = None
        record["report_url"] = None

        return record

    # Give the page a little time to render.
    await page.wait_for_timeout(2000)

    # --------------------------------------------------------
    # Extract malware name from the H1.
    # --------------------------------------------------------

    try:
        h1 = page.locator("h1").first

        if await h1.count():
            h1_text = clean_text(
                await h1.inner_text()
            )

            if h1_text:
                record["malware_name"] = h1_text

    except Exception:
        pass

    # --------------------------------------------------------
    # Extract TYPE.
    #
    # Current ANY.RUN trend pages expose text similar to:
    #
    #     Phishingkit Type | Unknown Origin
    #
    # or:
    #
    #     RAT Type | ...
    #
    # We inspect the page text rather than depending on a
    # fragile CSS class.
    # --------------------------------------------------------

    page_text = ""

    try:
        page_text = clean_text(
            await page.locator("body").inner_text()
        )
    except Exception:
        pass

    malware_type = None

    # Common types used by ANY.RUN.
    known_types = [
        "Phishingkit",
        "RAT",
        "Stealer",
        "Loader",
        "Ransomware",
        "Trojan",
        "Spyware",
        "Backdoor",
        "Infostealer",
        "Downloader",
        "Botnet",
        "Keylogger",
        "Dropper",
        "Crypter",
        "Clipper",
        "C2 Framework",
        "Banking trojan",
        "Remote access tool",
        "Penetration software"
    ]

    # First look for "<TYPE> Type".
    for candidate in known_types:

        pattern = (
            r"\b"
            + re.escape(candidate)
            + r"\s+Type\b"
        )

        if re.search(
            pattern,
            page_text,
            flags=re.IGNORECASE
        ):
            malware_type = candidate
            break

    # If that did not work, look for the type anywhere in the
    # first portion of the page.
    if malware_type is None:

        first_part = page_text[:5000]

        for candidate in known_types:

            pattern = (
                r"\b"
                + re.escape(candidate)
                + r"\b"
            )

            if re.search(
                pattern,
                first_part,
                flags=re.IGNORECASE
            ):
                malware_type = candidate
                break

    record["type"] = malware_type

    print(f"Type:    {malware_type}")

    # --------------------------------------------------------
    # Extract report URL.
    #
    # First look for /report/ links.
    # --------------------------------------------------------

    report_url = None

    report_links = page.locator(
        'a[href*="/report/"]'
    )

    report_count = await report_links.count()

    for i in range(report_count):

        try:
            href = await report_links.nth(i).get_attribute(
                "href"
            )
        except Exception:
            continue

        if not href:
            continue

        href = absolute_url(href)

        if "/report/" in href:
            report_url = href
            break

    # --------------------------------------------------------
    # Current ANY.RUN trend pages commonly expose sample
    # analysis links under app.any.run/tasks/...
    #
    # If a /report/ URL doesn't exist, use the actual sample
    # analysis URL.
    # --------------------------------------------------------

    if report_url is None:

        task_links = page.locator(
            'a[href*="app.any.run/tasks/"]'
        )

        task_count = await task_links.count()

        for i in range(task_count):

            try:
                href = await task_links.nth(i).get_attribute(
                    "href"
                )
            except Exception:
                continue

            if not href:
                continue

            if "app.any.run/tasks/" in href:

                report_url = href
                break

    # --------------------------------------------------------
    # Last fallback: inspect every anchor.
    # --------------------------------------------------------

    if report_url is None:

        all_links = page.locator("a")

        all_count = await all_links.count()

        for i in range(all_count):

            try:
                href = await all_links.nth(i).get_attribute(
                    "href"
                )
            except Exception:
                continue

            if not href:
                continue

            if "app.any.run/tasks/" in href:

                report_url = href
                break

    record["report_url"] = report_url

    print(f"Report:  {report_url}")

    return record


# ============================================================
# SAVE JSON
# ============================================================

def save_json(records):
    """Create the final requested JSON structure."""

    output = {
        "source": SOURCE_URL,
        "records_count": len(records),
        "records": []
    }

    for number, record in enumerate(records, start=1):

        output["records"].append(
            {
                "record_number": number,
                "malware_name": record.get(
                    "malware_name"
                ),
                "type": record.get(
                    "type"
                ),
                "trend_url": record.get(
                    "trend_url"
                ),
                "report_url": record.get(
                    "report_url"
                )
            }
        )

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

    return output


# ============================================================
# MAIN
# ============================================================

async def main():

    print()
    print("=" * 70)
    print("ANY.RUN TOP 20 MALWARE TRENDS SCRAPER")
    print("=" * 70)

    async with async_playwright() as playwright:

        # ----------------------------------------------------
        # Launch Chromium.
        # ----------------------------------------------------

        browser = await playwright.chromium.launch(
            headless=True
        )

        # ----------------------------------------------------
        # Create browser context.
        # ----------------------------------------------------

        context = await browser.new_context(
            viewport={
                "width": 1440,
                "height": 1000
            },
            locale="en-US",
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            )
        )

        # ----------------------------------------------------
        # Create page.
        # ----------------------------------------------------

        page = await context.new_page()

        page.set_default_timeout(30000)

        try:

            # =================================================
            # STEP 1
            # =================================================

            records = await get_top_trends(page)

            if not records:

                print()
                print("ERROR: No malware records found.")
                print()
                print("Possible causes:")
                print("1. ANY.RUN changed its HTML.")
                print("2. The page was blocked.")
                print("3. Chromium did not render the page.")
                print("4. Internet connection problem.")

                return

            print()
            print(
                f"Successfully found {len(records)} records."
            )

            # =================================================
            # STEP 2
            # Visit each malware trend page.
            # =================================================

            for index, record in enumerate(
                records,
                start=1
            ):

                print()
                print(
                    f"[{index}/{len(records)}]"
                )

                await get_trend_details(
                    page,
                    record
                )

                # Small delay.
                await page.wait_for_timeout(500)

            # =================================================
            # STEP 3
            # Save JSON.
            # =================================================

            output = save_json(records)

            # =================================================
            # STEP 4
            # Display final results.
            # =================================================

            print()
            print("=" * 70)
            print("SCRAPING COMPLETE")
            print("=" * 70)

            print(
                f"Source: {output['source']}"
            )

            print(
                f"Records: {output['records_count']}"
            )

            print(
                f"Output file: {OUTPUT_FILE}"
            )

            print("=" * 70)

            print()
            print("FINAL RECORDS")
            print("=" * 70)

            for record in output["records"]:

                print(
                    f"{record['record_number']}. "
                    f"{record['malware_name']} | "
                    f"{record['type']}"
                )

                print(
                    f"   Trend:  {record['trend_url']}"
                )

                print(
                    f"   Report: {record['report_url']}"
                )

        finally:

            await browser.close()


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    asyncio.run(main())