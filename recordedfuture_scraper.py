import asyncio
import json
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError


# ============================================================
# CONFIGURATION
# ============================================================

CATEGORY_URL = "https://therecord.media/news/cybercrime"
BASE_URL = "https://therecord.media"

NUMBER_OF_REPORTS = 5

OUTPUT_DIR = Path("output")
OUTPUT_FILE = OUTPUT_DIR / "therecord_cybercrime_latest_5.json"


# ============================================================
# TEXT CLEANING
# ============================================================

def clean_text(text):
    """
    Clean unnecessary whitespace while preserving paragraph
    separation.
    """

    if not text:
        return ""

    # Normalize Windows/newline characters
    text = text.replace("\r\n", "\n")
    text = text.replace("\r", "\n")

    # Remove spaces/tabs at line endings
    text = re.sub(r"[ \t]+", " ", text)

    # Remove excessive blank lines
    text = re.sub(r"\n[ \t]*\n[ \t]*\n+", "\n\n", text)

    # Clean individual lines
    lines = []

    for line in text.split("\n"):
        line = line.strip()

        if line:
            lines.append(line)

    return "\n\n".join(lines).strip()


# ============================================================
# URL FUNCTIONS
# ============================================================

def normalize_url(url):
    if not url:
        return ""

    return urljoin(BASE_URL, url)


def is_therecord_url(url):
    """
    Make sure URL belongs to therecord.media.
    """

    try:
        parsed = urlparse(url)

        return (
            parsed.scheme in ("http", "https")
            and parsed.netloc.lower() in (
                "therecord.media",
                "www.therecord.media"
            )
        )

    except Exception:
        return False


def looks_like_article_url(url):
    """
    Identify likely The Record article URLs.

    The Record commonly uses URLs such as:

    https://therecord.media/us-bank-breach-claims
    """

    if not url:
        return False

    url = normalize_url(url)

    if not is_therecord_url(url):
        return False

    parsed = urlparse(url)

    path = parsed.path.strip("/")

    if not path:
        return False

    # Pages that are not individual articles
    excluded = [
        "news",
        "news/cybercrime",
        "all-news",
        "about",
        "contact",
        "subscribe",
        "search",
        "podcast",
        "podcasts",
        "tag/cybercrime",
    ]

    if path.lower() in excluded:
        return False

    # Exclude obvious section/category pages
    excluded_prefixes = [
        "news/",
        "tag/",
        "author/",
        "category/",
    ]

    for prefix in excluded_prefixes:
        if path.lower().startswith(prefix):
            return False

    return True


# ============================================================
# SAFE LOCATOR FUNCTIONS
# ============================================================

async def get_text(page, selectors):
    """
    Try multiple selectors and return the first useful text.
    """

    for selector in selectors:

        try:

            locator = page.locator(selector)

            count = await locator.count()

            if count == 0:
                continue

            text = await locator.first.inner_text()

            text = clean_text(text)

            if text:
                return text

        except Exception:
            continue

    return ""


async def get_attribute(page, selectors, attribute):
    """
    Try multiple selectors and return the first attribute.
    """

    for selector in selectors:

        try:

            locator = page.locator(selector)

            if await locator.count() == 0:
                continue

            value = await locator.first.get_attribute(attribute)

            if value:
                return value.strip()

        except Exception:
            continue

    return ""


# ============================================================
# FIND ARTICLE LINKS
# ============================================================

async def find_article_links(page):

    print()
    print("=" * 70)
    print("OPENING CYBERCRIME PAGE")
    print("=" * 70)

    print(CATEGORY_URL)

    try:

        await page.goto(
            CATEGORY_URL,
            wait_until="domcontentloaded",
            timeout=60000
        )

    except PlaywrightTimeoutError:

        print("Page load timeout. Continuing...")

    await page.wait_for_timeout(4000)

    print("Page loaded.")

    # --------------------------------------------------------
    # Scroll to allow dynamically loaded articles to appear
    # --------------------------------------------------------

    for i in range(4):

        print(f"Scrolling {i + 1}/4")

        await page.mouse.wheel(0, 1200)

        await page.wait_for_timeout(1200)

    # Return to top
    await page.evaluate(
        "window.scrollTo(0, 0)"
    )

    await page.wait_for_timeout(1500)

    # --------------------------------------------------------
    # Extract all links
    # --------------------------------------------------------

    links = await page.locator("a").evaluate_all(
        """
        elements => elements.map(a => ({
            href: a.href,
            text: a.innerText
        }))
        """
    )

    article_links = []
    seen = set()

    for item in links:

        href = item.get("href", "")
        text = clean_text(item.get("text", ""))

        if not href:
            continue

        href = normalize_url(href)

        # Remove query string and fragment
        href = href.split("?")[0]
        href = href.split("#")[0]

        if not looks_like_article_url(href):
            continue

        if href in seen:
            continue

        seen.add(href)

        article_links.append({
            "url": href,
            "link_text": text
        })

    print()
    print(f"Possible article links found: {len(article_links)}")

    for i, article in enumerate(article_links[:15], 1):

        print(
            f"{i}. {article['link_text'][:80]}"
        )

        print(
            f"   {article['url']}"
        )

    return article_links


# ============================================================
# EXTRACT ARTICLE BODY
# ============================================================

async def extract_article_body(page):

    """
    Extract the actual article text.

    We intentionally extract paragraph elements instead
    of using article.inner_text() because the <article>
    container can contain author information, social buttons,
    related articles, newsletter elements, etc.
    """

    # --------------------------------------------------------
    # First preference: article paragraphs
    # --------------------------------------------------------

    paragraph_selectors = [
        "article p",
        "main article p",
        "[class*='article-body'] p",
        "[class*='ArticleBody'] p",
        "[class*='articleBody'] p",
        "[class*='post-content'] p",
        "[class*='PostContent'] p",
    ]

    for selector in paragraph_selectors:

        try:

            paragraphs = page.locator(selector)

            count = await paragraphs.count()

            if count == 0:
                continue

            extracted = []

            for i in range(count):

                try:

                    p = paragraphs.nth(i)

                    text = clean_text(
                        await p.inner_text()
                    )

                    if not text:
                        continue

                    # Ignore very common non-article elements
                    lower = text.lower()

                    ignored = [
                        "subscribe",
                        "sign up for",
                        "newsletter",
                        "follow us",
                        "share this article",
                    ]

                    if any(
                        phrase in lower
                        for phrase in ignored
                    ):
                        continue

                    extracted.append(text)

                except Exception:
                    continue

            if extracted:

                body = "\n\n".join(extracted)

                # Require reasonable article length
                if len(body) > 200:
                    return clean_text(body)

        except Exception:
            continue

    # --------------------------------------------------------
    # Fallback
    # --------------------------------------------------------

    fallback_selectors = [
        "article",
        "main article",
        "main",
    ]

    for selector in fallback_selectors:

        try:

            locator = page.locator(selector)

            if await locator.count() == 0:
                continue

            text = clean_text(
                await locator.first.inner_text()
            )

            if len(text) > 200:
                return text

        except Exception:
            continue

    return ""


# ============================================================
# EXTRACT SINGLE ARTICLE
# ============================================================

async def scrape_article(context, article_url, number):

    page = await context.new_page()

    print()
    print("-" * 70)
    print(f"ARTICLE {number}")
    print("-" * 70)

    print(article_url)

    try:

        try:

            await page.goto(
                article_url,
                wait_until="domcontentloaded",
                timeout=60000
            )

        except PlaywrightTimeoutError:

            print("Article page timeout. Continuing extraction...")

        # Give JavaScript time to render
        await page.wait_for_timeout(2500)

        # ----------------------------------------------------
        # TITLE
        # ----------------------------------------------------

        title = await get_text(
            page,
            [
                "article h1",
                "main h1",
                "h1",
            ]
        )

        # ----------------------------------------------------
        # AUTHOR
        # ----------------------------------------------------

        author = await get_text(
            page,
            [
                "[rel='author']",
                "a[href*='/author/']",
                "[class*='author']",
                "[class*='Author']",
                "[class*='byline']",
                "[class*='Byline']",
            ]
        )

        # Clean common prefixes
        author = re.sub(
            r"^\s*by\s+",
            "",
            author,
            flags=re.IGNORECASE
        )

        # ----------------------------------------------------
        # PUBLICATION DATE
        # ----------------------------------------------------

        publication_date = ""

        # Prefer datetime attribute
        try:

            time_locator = page.locator("time")

            if await time_locator.count() > 0:

                publication_date = (
                    await time_locator.first.get_attribute(
                        "datetime"
                    )
                    or ""
                )

                if not publication_date:

                    publication_date = clean_text(
                        await time_locator.first.inner_text()
                    )

        except Exception:
            pass

        # ----------------------------------------------------
        # DESCRIPTION = FULL ARTICLE BODY
        # ----------------------------------------------------

        description = await extract_article_body(
            page
        )

        # ----------------------------------------------------
        # FALLBACK TO META DESCRIPTION
        # ----------------------------------------------------

        if not description:

            description = await get_attribute(
                page,
                [
                    "meta[name='description']",
                    "meta[property='og:description']",
                ],
                "content"
            )

        # ----------------------------------------------------
        # REMOVE OBVIOUS WEBSITE FOOTER TEXT
        # ----------------------------------------------------

        description = clean_text(description)

        # ----------------------------------------------------
        # RESULT
        # ----------------------------------------------------

        result = {
            "author": author,
            "title": title,
            "description": description,
            "publication_date": publication_date,
            "url": article_url
        }

        print()
        print("Author:")
        print(author)

        print()
        print("Title:")
        print(title)

        print()
        print("Description characters:")
        print(len(description))

        await page.close()

        return result

    except Exception as e:

        print(
            f"ERROR scraping article: {e}"
        )

        try:
            await page.close()
        except Exception:
            pass

        return None


# ============================================================
# MAIN
# ============================================================

async def main():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    async with async_playwright() as playwright:

        print()
        print("=" * 70)
        print("STARTING PLAYWRIGHT")
        print("=" * 70)

        browser = await playwright.chromium.launch(
            headless=True
        )

        context = await browser.new_context(
            viewport={
                "width": 1366,
                "height": 900
            },
            locale="en-US",
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/151.0.0.0 Safari/537.36"
            )
        )

        page = await context.new_page()

        # ----------------------------------------------------
        # STEP 1
        # Find articles on Cybercrime page
        # ----------------------------------------------------

        article_links = await find_article_links(
            page
        )

        await page.close()

        # ----------------------------------------------------
        # STEP 2
        # Scrape latest 5
        # ----------------------------------------------------

        reports = []

        for article in article_links:

            if len(reports) >= NUMBER_OF_REPORTS:
                break

            result = await scrape_article(
                context,
                article["url"],
                len(reports) + 1
            )

            if not result:
                continue

            # Don't save pages without a title/body
            if not result["title"]:
                print(
                    "Skipping: title not found."
                )
                continue

            if not result["description"]:
                print(
                    "Skipping: article body not found."
                )
                continue

            reports.append(result)

            print()
            print(
                f"Successfully scraped "
                f"{len(reports)}/{NUMBER_OF_REPORTS}"
            )

        # ----------------------------------------------------
        # STEP 3
        # Save JSON
        # ----------------------------------------------------

        output = {
            "source": CATEGORY_URL,
            "category": "Cybercrime",
            "scraped_at": datetime.now().isoformat(),
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

        # ----------------------------------------------------
        # FINAL MESSAGE
        # ----------------------------------------------------

        print()
        print("=" * 70)
        print("SCRAPING FINISHED")
        print("=" * 70)

        print(
            f"Reports scraped: {len(reports)}"
        )

        print(
            f"Output file: {OUTPUT_FILE}"
        )

        print("=" * 70)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    asyncio.run(main())