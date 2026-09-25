import json
from pathlib import Path
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError


URL = "https://threatfox.abuse.ch/browse/"
OUTPUT_FILE = "threatfox_top20.json"


def clean_text(text):
    """Normalize whitespace."""
    if not text:
        return ""
    return " ".join(text.split())


def get_tags(cell):
    """
    Extract all tag text from a table cell.
    Tags are represented by links on the ThreatFox page.
    """
    tags = []

    for link in cell.locator("a").all():
        text = clean_text(link.inner_text())
        if text:
            tags.append(text)

    # Remove duplicates while preserving order
    return list(dict.fromkeys(tags))


def scrape_threatfox():
    with sync_playwright() as p:

        browser = p.chromium.launch(
            headless=False
        )

        context = browser.new_context(
            viewport={"width": 1440, "height": 1000}
        )

        page = context.new_page()

        print("Opening ThreatFox...")
        page.goto(
            URL,
            wait_until="domcontentloaded",
            timeout=60_000
        )

        print("\nIf ThreatFox displays an hCaptcha:")
        print("1. Complete the CAPTCHA manually in the browser.")
        print("2. Return to this terminal.")
        print("3. Press ENTER to continue.\n")

        input("Press ENTER after the CAPTCHA has been completed... ")

        # Give the page a moment to finish any post-CAPTCHA requests.
        page.wait_for_timeout(2000)

        # Find tables on the page.
        tables = page.locator("table")

        if tables.count() == 0:
            raise RuntimeError(
                "No table was found. Check whether the page loaded correctly."
            )

        print(f"Found {tables.count()} table(s).")

        # Find the table containing the expected headers.
        target_table = None

        for i in range(tables.count()):
            table = tables.nth(i)

            headers = [
                clean_text(x)
                for x in table.locator("thead th").all_inner_texts()
            ]

            header_string = " ".join(headers).lower()

            if (
                "ioc" in header_string
                and "malware" in header_string
                and "reporter" in header_string
            ):
                target_table = table
                print(f"Using table #{i + 1}")
                break

        if target_table is None:
            raise RuntimeError(
                "Could not identify the ThreatFox IOC table."
            )

        # Get table rows.
        rows = target_table.locator("tbody tr")

        row_count = rows.count()

        print(f"Rows found: {row_count}")

        results = []

        for index in range(min(20, row_count)):

            row = rows.nth(index)
            cells = row.locator("td")

            cell_count = cells.count()

            if cell_count < 5:
                print(
                    f"Skipping row {index + 1}: "
                    f"only {cell_count} cells found."
                )
                continue

            # Current ThreatFox table:
            #
            # 0 = Date
            # 1 = IOC
            # 2 = Malware
            # 3 = Tags
            # 4 = Reporter

            ioc_cell = cells.nth(1)
            malware_cell = cells.nth(2)
            tags_cell = cells.nth(3)
            reporter_cell = cells.nth(4)

            ioc = clean_text(ioc_cell.inner_text())
            malware = clean_text(malware_cell.inner_text())
            reporter = clean_text(reporter_cell.inner_text())

            tags = get_tags(tags_cell)

            # IOC/record link
            ioc_link = ""

            links = ioc_cell.locator("a")

            if links.count() > 0:
                ioc_link = links.first.get_attribute("href") or ""

                if ioc_link:
                    ioc_link = page.url.split("/browse/")[0] + ioc_link \
                        if ioc_link.startswith("/") \
                        else ioc_link

            # Prefer the actual malware detail link as a fallback record URL
            if not ioc_link:
                malware_links = malware_cell.locator("a")

                if malware_links.count() > 0:
                    ioc_link = (
                        malware_links.first.get_attribute("href") or ""
                    )

                    if ioc_link.startswith("/"):
                        ioc_link = page.url.split("/browse/")[0] + ioc_link

            record = {
                "record_number": index + 1,
                "malware_name": malware,
                "tags": tags,
                "reporter": reporter,
                "ioc": ioc,
                "record_link": ioc_link
            }

            results.append(record)

            print(
                f"[{index + 1:02d}] "
                f"{malware} | {ioc} | {reporter}"
            )

        # Save JSON
        output_path = Path(OUTPUT_FILE)

        with output_path.open(
            "w",
            encoding="utf-8"
        ) as f:
            json.dump(
                results,
                f,
                indent=4,
                ensure_ascii=False
            )

        print("\n--------------------------------")
        print(f"Scraped {len(results)} records.")
        print(f"JSON saved to: {output_path.resolve()}")
        print("--------------------------------")

        browser.close()


if __name__ == "__main__":
    scrape_threatfox()
