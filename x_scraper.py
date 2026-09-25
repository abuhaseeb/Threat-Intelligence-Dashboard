import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from Scweet import Scweet


# ============================================================
# CONFIGURATION
# ============================================================

AUTH_TOKEN = ""  # provided at runtime from the dashboard UI; never hardcode real tokens here

TARGET_USERNAME = "Cyberteam008"

NUMBER_OF_POSTS = 10

OUTPUT_FILE = "cybersignal_posts.json"


# ============================================================
# REGEX PATTERNS FOR IOC EXTRACTION
# ============================================================

IPV4_PATTERN = re.compile(
    r"\b"
    r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"\b"
)

DOMAIN_PATTERN = re.compile(
    r"\b"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}"
    r"\b"
)

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
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

MITRE_PATTERN = re.compile(
    r"\bT\d{4}(?:\.\d{3})?\b",
    re.IGNORECASE
)


# ============================================================
# GENERAL HELPERS
# ============================================================

def first_value(data, keys, default=None):
    """
    Return the first non-empty value from a dictionary.
    """

    if not isinstance(data, dict):
        return default

    for key in keys:
        value = data.get(key)

        if value is not None and value != "":
            return value

    return default


def normalize_text(value):
    """
    Convert a possible Scweet value into clean text.
    """

    if value is None:
        return ""

    if isinstance(value, str):
        return value.strip()

    return str(value).strip()


def safe_list(value):
    """
    Convert None/single values into a list.
    """

    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


# ============================================================
# TEXT EXTRACTION
# ============================================================

def extract_urls(text):
    """
    Extract HTTP/HTTPS URLs from text.
    """

    if not text:
        return []

    urls = URL_PATTERN.findall(text)

    cleaned = []

    for url in urls:
        url = url.rstrip(".,;:!?)]}")

        if url not in cleaned:
            cleaned.append(url)

    return cleaned


def extract_iocs(text):
    """
    Extract common cybersecurity indicators from post text.
    """

    if not text:
        return {
            "ipv4": [],
            "domains": [],
            "urls": [],
            "emails": [],
            "md5": [],
            "sha1": [],
            "sha256": [],
            "cves": [],
            "mitre_attack": []
        }

    urls = extract_urls(text)

    ipv4 = sorted(set(IPV4_PATTERN.findall(text)))

    emails = sorted(set(EMAIL_PATTERN.findall(text)))

    md5 = sorted(set(MD5_PATTERN.findall(text)))

    sha1 = sorted(set(SHA1_PATTERN.findall(text)))

    sha256 = sorted(set(SHA256_PATTERN.findall(text)))

    cves = sorted(
        set(
            item.upper()
            for item in CVE_PATTERN.findall(text)
        )
    )

    mitre_attack = sorted(
        set(
            item.upper()
            for item in MITRE_PATTERN.findall(text)
        )
    )

    domains = set()

    # Domains from explicit URLs
    for url in urls:
        try:
            parsed = urlparse(url)

            if parsed.hostname:
                domains.add(parsed.hostname.lower())

        except Exception:
            pass

    # Domains appearing directly in text
    for domain in DOMAIN_PATTERN.findall(text):
        domain = domain.lower()

        # Avoid treating email domains as standalone IOCs
        if not any(
            email.lower().endswith("@" + domain)
            for email in emails
        ):
            domains.add(domain)

    # Remove IPs from domains
    domains = {
        domain
        for domain in domains
        if not IPV4_PATTERN.fullmatch(domain)
    }

    return {
        "ipv4": ipv4,
        "domains": sorted(domains),
        "urls": urls,
        "emails": emails,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "cves": cves,
        "mitre_attack": mitre_attack
    }


# ============================================================
# HASHTAGS / MENTIONS
# ============================================================

def extract_hashtags(text):
    if not text:
        return []

    hashtags = re.findall(
        r"(?<!\w)#([A-Za-z0-9_]+)",
        text
    )

    return sorted(set(hashtags))


def extract_mentions(text):
    if not text:
        return []

    mentions = re.findall(
        r"(?<!\w)@([A-Za-z0-9_]{1,15})",
        text
    )

    return sorted(set(mentions))


# ============================================================
# MEDIA EXTRACTION
# ============================================================

def extract_media(tweet):
    """
    Extract media from several possible Scweet/X field names.

    Scweet/X response structures can change, so this function
    intentionally checks multiple common representations.
    """

    media_output = []

    possible_media_keys = [
        "media",
        "media_urls",
        "media_url",
        "media_url_https",
        "photos",
        "images",
        "videos",
        "extended_entities"
    ]

    for key in possible_media_keys:

        value = tweet.get(key)

        if value is None:
            continue

        values = safe_list(value)

        for item in values:

            if isinstance(item, str):

                media_output.append({
                    "type": "unknown",
                    "url": item
                })

            elif isinstance(item, dict):

                media_type = first_value(
                    item,
                    [
                        "type",
                        "media_type",
                        "content_type"
                    ],
                    "unknown"
                )

                media_url = first_value(
                    item,
                    [
                        "url",
                        "media_url",
                        "media_url_https",
                        "expanded_url"
                    ]
                )

                if media_url:

                    media_output.append({
                        "type": normalize_text(media_type),
                        "url": normalize_text(media_url)
                    })

    # Remove duplicates
    unique_media = []

    seen = set()

    for media in media_output:

        key = (
            media.get("type"),
            media.get("url")
        )

        if key not in seen:
            seen.add(key)
            unique_media.append(media)

    return unique_media


# ============================================================
# POST TYPE
# ============================================================

def determine_post_type(tweet, text):
    """
    Determine whether a post is:
      - original
      - reply
      - repost
      - quote
      - thread_post
      - unknown
    """

    # Repost / retweet
    if any(
        tweet.get(key)
        for key in [
            "retweeted_status",
            "retweeted_tweet",
            "repost",
            "is_retweet"
        ]
    ):
        return "repost"

    # Quote
    if any(
        tweet.get(key)
        for key in [
            "quoted_status",
            "quoted_tweet",
            "quote"
        ]
    ):
        return "quote"

    # Reply
    if any(
        tweet.get(key)
        for key in [
            "in_reply_to_status_id",
            "in_reply_to_tweet_id",
            "in_reply_to_user_id",
            "in_reply_to_screen_name",
            "reply_to"
        ]
    ):
        return "reply"

    # X posts beginning with @ are frequently replies
    if text.startswith("@"):
        return "reply"

    return "original"


# ============================================================
# AUTHOR EXTRACTION
# ============================================================

def extract_author(tweet):
    """
    Extract author information from different possible
    Scweet/X response structures.
    """

    author = tweet.get("user")

    if isinstance(author, dict):

        username = first_value(
            author,
            [
                "username",
                "screen_name",
                "handle"
            ],
            TARGET_USERNAME
        )

        display_name = first_value(
            author,
            [
                "name",
                "display_name"
            ],
            username
        )

        user_id = first_value(
            author,
            [
                "id",
                "user_id",
                "rest_id"
            ]
        )

        return {
            "username": normalize_text(username),
            "display_name": normalize_text(display_name),
            "user_id": normalize_text(user_id)
        }

    username = first_value(
        tweet,
        [
            "username",
            "screen_name",
            "author_username",
            "user_screen_name"
        ],
        TARGET_USERNAME
    )

    display_name = first_value(
        tweet,
        [
            "author_name",
            "name",
            "display_name"
        ],
        username
    )

    user_id = first_value(
        tweet,
        [
            "user_id",
            "author_id",
            "rest_id"
        ]
    )

    return {
        "username": normalize_text(username),
        "display_name": normalize_text(display_name),
        "user_id": normalize_text(user_id)
    }


# ============================================================
# TITLE EXTRACTION
# ============================================================

def generate_title(text):
    """
    X posts don't normally have a separate title field.
    Therefore, create a useful title from the first sentence
    or first ~100 characters.
    """

    if not text:
        return ""

    cleaned = " ".join(text.split())

    # Remove leading mentions for title generation
    cleaned = re.sub(
        r"^(?:@\w+\s*)+",
        "",
        cleaned
    ).strip()

    if not cleaned:
        return ""

    # First sentence
    sentence_match = re.split(
        r"(?<=[.!?])\s+",
        cleaned
    )

    title = sentence_match[0]

    # Keep title reasonably short
    if len(title) > 100:
        title = title[:97] + "..."

    return title


# ============================================================
# POST ID
# ============================================================

def extract_post_id(tweet):
    return normalize_text(
        first_value(
            tweet,
            [
                "id",
                "id_str",
                "tweet_id",
                "status_id",
                "rest_id"
            ]
        )
    )


# ============================================================
# POST URL
# ============================================================

def extract_post_url(tweet, author):
    """
    Generate the X post URL when an ID is available.
    """

    post_id = extract_post_id(tweet)

    username = author.get("username")

    if post_id and username:
        return f"https://x.com/{username}/status/{post_id}"

    # Check if Scweet already supplied a URL
    url = first_value(
        tweet,
        [
            "url",
            "tweet_url",
            "status_url",
            "link"
        ]
    )

    return normalize_text(url)


# ============================================================
# RAW TWEET NORMALIZATION
# ============================================================

def normalize_post(tweet, thread_position=None):
    """
    Convert Scweet's raw post dictionary into the required
    structured JSON format.
    """

    if not isinstance(tweet, dict):
        tweet = {}

    text = normalize_text(
        first_value(
            tweet,
            [
                "text",
                "full_text",
                "content",
                "tweet_text",
                "description",
                "selftext"
            ],
            ""
        )
    )

    author = extract_author(tweet)

    media = extract_media(tweet)

    iocs = extract_iocs(text)

    post_type = determine_post_type(
        tweet,
        text
    )

    post_id = extract_post_id(tweet)

    created_at = normalize_text(
        first_value(
            tweet,
            [
                "created_at",
                "date",
                "timestamp",
                "created"
            ]
        )
    )

    conversation_id = normalize_text(
        first_value(
            tweet,
            [
                "conversation_id",
                "conversationId",
                "conversation_id_str"
            ]
        )
    )

    reply_to_id = normalize_text(
        first_value(
            tweet,
            [
                "in_reply_to_status_id",
                "in_reply_to_tweet_id",
                "reply_to_id"
            ]
        )
    )

    post = {
        "title": generate_title(text),

        "author": author,

        "post_body_selftext": text,

        "post_type": post_type,

        "media": media,

        "iocs": iocs,

        "hashtags": extract_hashtags(text),

        "mentions": extract_mentions(text),

        "post_id": post_id,

        "post_url": extract_post_url(
            tweet,
            author
        ),

        "created_at": created_at,

        "thread_metadata": {
            "conversation_id": conversation_id,
            "reply_to_post_id": reply_to_id,
            "thread_position": thread_position
        }
    }

    return post


# ============================================================
# THREAD DETECTION
# ============================================================

def get_thread_key(raw_tweet):
    """
    Determine the best available conversation/thread key.
    """

    if not isinstance(raw_tweet, dict):
        return None

    conversation_id = first_value(
        raw_tweet,
        [
            "conversation_id",
            "conversationId",
            "conversation_id_str"
        ]
    )

    if conversation_id:
        return str(conversation_id)

    # If no conversation ID exists, use reply chain ID
    reply_to = first_value(
        raw_tweet,
        [
            "in_reply_to_status_id",
            "in_reply_to_tweet_id",
            "reply_to_id"
        ]
    )

    if reply_to:
        return f"reply:{reply_to}"

    return None


def build_threads(raw_posts):
    """
    Group posts that have the same conversation ID.

    Posts without reliable thread metadata remain individual
    posts rather than being incorrectly grouped.
    """

    thread_groups = {}

    standalone_posts = []

    for index, raw_post in enumerate(raw_posts):

        thread_key = get_thread_key(raw_post)

        if thread_key:

            thread_groups.setdefault(
                thread_key,
                []
            ).append(
                (index, raw_post)
            )

        else:

            standalone_posts.append(
                (index, raw_post)
            )

    threads = []

    for thread_key, items in thread_groups.items():

        # A single post is not really a thread
        if len(items) < 2:
            continue

        items.sort(key=lambda item: item[0])

        thread_posts = []

        for position, (_, raw_post) in enumerate(items, start=1):

            normalized = normalize_post(
                raw_post,
                thread_position=position
            )

            thread_posts.append(normalized)

        threads.append({
            "thread_id": thread_key,
            "thread_length": len(thread_posts),
            "posts": thread_posts
        })

    return threads


# ============================================================
# RAW DATA FIELD INSPECTION
# ============================================================

def print_raw_structure(posts):
    """
    Print available fields from the first result.
    This is useful because X/Scweet fields can change.
    """

    if not posts:
        print("\nNo posts returned.")
        return

    first = posts[0]

    if isinstance(first, dict):

        print("\nAvailable fields in first Scweet result:")

        for key in sorted(first.keys()):
            print(f"  - {key}")


# ============================================================
# MAIN SCRAPER
# ============================================================

def main():

    print("=" * 70)
    print("X.COM CYBERSIGNAL SCRAPER")
    print("=" * 70)

    if (
        not AUTH_TOKEN
        or AUTH_TOKEN == "PUT_YOUR_AUTH_TOKEN_HERE"
    ):
        raise ValueError(
            "\nPlease put your X auth_token in AUTH_TOKEN "
            "inside scraper.py."
        )

    print(f"\nTarget account : @{TARGET_USERNAME}")
    print(f"Posts requested: {NUMBER_OF_POSTS}")
    print("Authentication : auth_token")

    print("\nInitializing Scweet...")

    scraper = Scweet(
        auth_token=AUTH_TOKEN,

        # Ask Scweet to refresh its X web manifest if necessary.
        manifest_scrape_on_init=True
    )

    print("Scweet initialized.")

    print(
        f"\nFetching latest {NUMBER_OF_POSTS} posts "
        f"from @{TARGET_USERNAME}..."
    )

    try:

        raw_posts = scraper.get_profile_tweets(
            [TARGET_USERNAME],
            limit=NUMBER_OF_POSTS
        )

    except Exception as exc:

        print("\nERROR while scraping:")
        print(type(exc).__name__)
        print(str(exc))

        raise

    # Make sure we have a list
    if raw_posts is None:
        raw_posts = []

    raw_posts = list(raw_posts)

    print(
        f"\nScweet returned {len(raw_posts)} raw posts."
    )

    # Show fields for debugging
    print_raw_structure(raw_posts)

    # --------------------------------------------------------
    # Normalize posts
    # --------------------------------------------------------

    normalized_posts = []

    for index, raw_post in enumerate(raw_posts[:NUMBER_OF_POSTS], start=1):

        post = normalize_post(
            raw_post,
            thread_position=None
        )

        normalized_posts.append(post)

        print(
            f"\n[{index}/{min(len(raw_posts), NUMBER_OF_POSTS)}]"
        )

        print(
            "Post ID:",
            post["post_id"]
        )

        print(
            "Type:",
            post["post_type"]
        )

        print(
            "Author:",
            post["author"]["username"]
        )

        print(
            "Body:",
            post["post_body_selftext"][:150]
        )

    # --------------------------------------------------------
    # Detect threads
    # --------------------------------------------------------

    threads = build_threads(
        raw_posts[:NUMBER_OF_POSTS]
    )

    # --------------------------------------------------------
    # Final JSON
    # --------------------------------------------------------

    output = {
        "source": "X.com",

        "target_account": {
            "username": TARGET_USERNAME,
            "url": f"https://x.com/{TARGET_USERNAME}"
        },

        "scraped_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "requested_posts": NUMBER_OF_POSTS,

        "posts_returned": len(normalized_posts),

        "posts": normalized_posts,

        "threads": threads,

        "thread_count": len(threads)
    }

    # --------------------------------------------------------
    # Save JSON
    # --------------------------------------------------------

    output_path = Path(OUTPUT_FILE)

    output_path.write_text(
        json.dumps(
            output,
            indent=4,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    print("\n" + "=" * 70)
    print("SCRAPING COMPLETED")
    print("=" * 70)

    print(
        f"\nJSON saved to:\n{output_path.resolve()}"
    )

    print(
        f"\nPosts saved : {len(normalized_posts)}"
    )

    print(
        f"Threads found: {len(threads)}"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()