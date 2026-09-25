import asyncio
import json
import re
from urllib.parse import urljoin

from playwright.async_api import async_playwright


# ============================================================
# CONFIGURATION
# ============================================================

URL = "https://malpedia.caad.fkie.fraunhofer.de/families"
BASE_URL = "https://malpedia.caad.fkie.fraunhofer.de"
OUTPUT_FILE = "malpedia_top20.json"
TOP_N = 20


# ============================================================
# OPERATING SYSTEM MAPPING
# ============================================================

OS_MAPPING = {
    "win": "Windows",
    "elf": "Linux",
    "apk": "Android",
    "js": "JavaScript",
    "ios": "iOS",
    "osx": "macOS",
    "jar": "Java",
    "py": "Python",
    "ps1": "PowerShell",
    "vba": "VBA",
    "doc": "Microsoft Office",
    "xls": "Microsoft Office",
}


# ============================================================
# TEXT CLEANING
# ============================================================

def clean_text(text):
    """
    Clean whitespace and non-breaking spaces.
    """

    if text is None:
        return ""

    text = str(text)

    # Replace non-breaking spaces
    text = text.replace("\xa0", " ")

    # Replace multiple whitespace characters
    text = re.sub(r"\s+", " ", text)

    return text.strip()


# ============================================================
# NORMALIZE HEADER
# ============================================================

def normalize_header(header):
    """
    Convert headers such as:

        Common Name
        Common\xa0Name

    into:

        commonname
    """

    header = clean_text(header)

    return (
        header
        .lower()
        .replace(" ", "")
        .replace("_", "")
        .replace("-", "")
    )


# ============================================================
# DETERMINE OS FROM MALPEDIA NAME
# ============================================================

def determine_os_from_name(name):
    """
    Determine operating system from the Malpedia Name.

    Examples:

        win.remus       -> Windows
        js.smartapesg   -> JavaScript
        elf.redshell    -> Linux
        apk.example     -> Android
    """

    if not name:
        return ""

    name = clean_text(name).lower()

    # Name normally has the form:
    #
    #     win.remus
    #     elf.redshell
    #     js.smartapesg

    prefix = name.split(".", 1)[0]

    return OS_MAPPING.get(prefix, prefix)


# ============================================================
# EXTRACT OS FROM TABLE CELL
# ============================================================

async def extract_os_from_cell(cell):
    """
    Try to obtain OS directly from the table cell.

    Malpedia may use text, icons, title attributes,
    aria-labels, alt text, etc.
    """

    # --------------------------------------------------------
    # 1. Try normal visible text
    # --------------------------------------------------------

    text = clean_text(await cell.inner_text())

    if text:
        return text


    # --------------------------------------------------------
    # 2. Inspect HTML attributes
    # --------------------------------------------------------

    attributes = await cell.evaluate(
        """
        element => {
            const values = [];

            function inspect(node) {
                if (!node) {
                    return;
                }

                const attributeNames = [
                    "title",
                    "aria-label",
                    "alt",
                    "data-original-title",
                    "data-tooltip",
                    "data-bs-original-title",
                    "class"
                ];

                for (const attribute of attributeNames) {
                    const value = node.getAttribute(attribute);

                    if (value) {
                        values.push(value);
                    }
                }

                for (const child of node.children) {
                    inspect(child);
                }
            }

            inspect(element);

            return values;
        }
        """
    )


    # --------------------------------------------------------
    # 3. Search for known OS names
    # --------------------------------------------------------

    known_operating_systems = [
        "Windows",
        "Linux",
        "Android",
        "JavaScript",
        "iOS",
        "macOS",
        "Java",
        "Python",
        "PowerShell",
        "VBA",
        "Microsoft Office",
    ]

    for attribute in attributes:

        attribute = clean_text(attribute)

        for operating_system in known_operating_systems:

            if operating_system.lower() in attribute.lower():
                return operating_system


    return ""


# ============================================================
# FIND MALPEDIA FAMILY TABLE
# ============================================================

async def find_family_table(page):
    """
    Find the table containing:

        OS
        Common Name
        Name

    instead of assuming it is the first table.
    """

    tables = page.locator("table")

    table_count = await tables.count()

    print(f"Tables found: {table_count}")

    for table_index in range(table_count):

        table = tables.nth(table_index)

        headers = await table.locator(
            "thead th"
        ).all_text_contents()

        headers = [
            clean_text(header)
            for header in headers
        ]

        normalized_headers = [
            normalize_header(header)
            for header in headers
        ]

        print(
            f"Table {table_index + 1} headers: "
            f"{headers}"
        )

        if (
            "commonname" in normalized_headers
            and "name" in normalized_headers
        ):

            print(
                f"Using table {table_index + 1}"
            )

            return table


    raise RuntimeError(
        "Could not find Malpedia families table."
    )


# ============================================================
# FIND COLUMN INDEXES
# ============================================================

async def get_column_indexes(table):

    headers = await table.locator(
        "thead th"
    ).all_text_contents()

    headers = [
        clean_text(header)
        for header in headers
    ]

    normalized_headers = [
        normalize_header(header)
        for header in headers
    ]

    print()
    print("Detected table headers:")
    print(headers)
    print()

    indexes = {
        "os": None,
        "common_name": None,
        "name": None,
    }

    for index, header in enumerate(
        normalized_headers
    ):

        if header == "os":
            indexes["os"] = index

        elif header == "commonname":
            indexes["common_name"] = index

        elif header == "name":
            indexes["name"] = index


    print(
        f"OS column index: "
        f"{indexes['os']}"
    )

    print(
        f"Common Name column index: "
        f"{indexes['common_name']}"
    )

    print(
        f"Name column index: "
        f"{indexes['name']}"
    )

    print()


    if indexes["common_name"] is None:
        raise RuntimeError(
            "Common Name column was not found."
        )

    if indexes["name"] is None:
        raise RuntimeError(
            "Name column was not found."
        )

    return indexes


# ============================================================
# EXTRACT DETAILS LINK
# ============================================================

async def extract_details_link(row, name):

    # --------------------------------------------------------
    # Method 1:
    # Look for normal <a href="">
    # --------------------------------------------------------

    anchors = row.locator("a")

    anchor_count = await anchors.count()

    for index in range(anchor_count):

        href = await anchors.nth(
            index
        ).get_attribute("href")

        if href and "/details/" in href:

            return urljoin(
                BASE_URL,
                href
            )


    # --------------------------------------------------------
    # Method 2:
    # Search elements with URL-related attributes
    # --------------------------------------------------------

    elements = row.locator(
        "[href], [data-href], [data-url], [data-link]"
    )

    element_count = await elements.count()

    for index in range(element_count):

        element = elements.nth(index)

        attributes = [
            "href",
            "data-href",
            "data-url",
            "data-link",
        ]

        for attribute in attributes:

            value = await element.get_attribute(
                attribute
            )

            if value and "/details/" in value:

                return urljoin(
                    BASE_URL,
                    value
                )


    # --------------------------------------------------------
    # Method 3:
    # Build URL from Name
    #
    # Example:
    #
    # win.remus
    #
    # ->
    #
    # https://malpedia.caad.fkie.fraunhofer.de/details/win.remus
    # --------------------------------------------------------

    name = clean_text(name)

    if name:

        return (
            f"{BASE_URL}/details/"
            f"{name}"
        )


    return ""


# ============================================================
# SCRAPE MALPEDIA
# ============================================================

async def scrape_malpedia():

    async with async_playwright() as playwright:

        print("Launching Chromium...")

        browser = await playwright.chromium.launch(
            headless=True
        )

        context = await browser.new_context(
            viewport={
                "width": 1920,
                "height": 1080,
            },
            user_agent=(
                "Mozilla/5.0 "
                "(Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/140.0.0.0 "
                "Safari/537.36"
            ),
        )

        page = await context.new_page()


        # ====================================================
        # OPEN PAGE
        # ====================================================

        print()
        print(
            f"Opening: {URL}"
        )

        await page.goto(
            URL,
            wait_until="networkidle",
            timeout=60000,
        )


        # ====================================================
        # WAIT FOR TABLE
        # ====================================================

        await page.wait_for_selector(
            "table",
            timeout=30000,
        )

        # Allow JavaScript/DataTables to finish
        await page.wait_for_timeout(2000)


        # ====================================================
        # FIND CORRECT TABLE
        # ====================================================

        table = await find_family_table(
            page
        )


        # ====================================================
        # FIND COLUMNS
        # ====================================================

        indexes = await get_column_indexes(
            table
        )

        os_index = indexes["os"]
        common_name_index = indexes[
            "common_name"
        ]
        name_index = indexes["name"]


        # ====================================================
        # GET ROWS
        # ====================================================

        rows = table.locator(
            "tbody tr"
        )

        row_count = await rows.count()

        print(
            f"Rows currently visible: "
            f"{row_count}"
        )

        print()


        # ====================================================
        # SCRAPE RECORDS
        # ====================================================

        records = []

        for row_index in range(
            row_count
        ):

            # Stop once 20 valid records
            # have been collected.
            if len(records) >= TOP_N:
                break


            row = rows.nth(
                row_index
            )

            cells = row.locator(
                "td"
            )

            cell_count = await cells.count()


            # ------------------------------------------------
            # Validate row
            # ------------------------------------------------

            if cell_count == 0:
                continue

            if cell_count <= name_index:

                print(
                    f"Skipping row "
                    f"{row_index + 1}: "
                    f"not enough cells."
                )

                continue


            # ------------------------------------------------
            # Extract Common Name
            # ------------------------------------------------

            malware_name = clean_text(
                await cells.nth(
                    common_name_index
                ).inner_text()
            )


            # ------------------------------------------------
            # Extract Name
            # ------------------------------------------------

            family_name = clean_text(
                await cells.nth(
                    name_index
                ).inner_text()
            )


            # ------------------------------------------------
            # Ignore empty rows
            # ------------------------------------------------

            if not malware_name:

                print(
                    f"Skipping row "
                    f"{row_index + 1}: "
                    f"empty Common Name."
                )

                continue


            if not family_name:

                print(
                    f"Skipping row "
                    f"{row_index + 1}: "
                    f"empty Name."
                )

                continue


            # ------------------------------------------------
            # Extract OS
            # ------------------------------------------------

            operating_system = ""

            if os_index is not None:

                operating_system = (
                    await extract_os_from_cell(
                        cells.nth(
                            os_index
                        )
                    )
                )


            # ------------------------------------------------
            # Fallback OS detection
            # ------------------------------------------------

            if not operating_system:

                operating_system = (
                    determine_os_from_name(
                        family_name
                    )
                )


            # ------------------------------------------------
            # Extract details link
            # ------------------------------------------------

            link = await extract_details_link(
                row,
                family_name
            )


            if not link:

                print(
                    f"Skipping row "
                    f"{row_index + 1}: "
                    f"no link."
                )

                continue


            # ------------------------------------------------
            # Create record
            # ------------------------------------------------

            record = {
                "record_number": len(records) + 1,
                "malware_name": malware_name,
                "operating_system": operating_system,
                "link": link,
            }


            records.append(
                record
            )


            # ------------------------------------------------
            # Print record
            # ------------------------------------------------

            print(
                f"Record "
                f"{record['record_number']}:"
            )

            print(
                f"  Malware name: "
                f"{record['malware_name']}"
            )

            print(
                f"  Operating system: "
                f"{record['operating_system']}"
            )

            print(
                f"  Link: "
                f"{record['link']}"
            )

            print()


        # ====================================================
        # CHECK RESULT
        # ====================================================

        print("=" * 60)

        print(
            f"Total records extracted: "
            f"{len(records)}"
        )

        print("=" * 60)


        if len(records) < TOP_N:

            print(
                f"WARNING: Expected "
                f"{TOP_N} records but only "
                f"{len(records)} were extracted."
            )


        # ====================================================
        # SAVE JSON
        # ====================================================

        with open(
            OUTPUT_FILE,
            "w",
            encoding="utf-8",
        ) as json_file:

            json.dump(
                records,
                json_file,
                indent=2,
                ensure_ascii=False,
            )


        print()
        print(
            f"JSON file created: "
            f"{OUTPUT_FILE}"
        )


        # ====================================================
        # CLOSE BROWSER
        # ====================================================

        await browser.close()


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    asyncio.run(
        scrape_malpedia()
    )
