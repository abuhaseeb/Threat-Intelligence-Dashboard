"""
Generates a short description for each scraped item using newspaper3k.

newspaper3k needs its own network fetch of the article URL plus NLTK's
'punkt' tokenizer data (see requirements.txt / README for setup). Both of
those can fail for reasons that have nothing to do with the dashboard
(paywalls, JS-only pages, offline dev box, missing punkt data), so every
failure here falls back to whatever description/snippet text the
original scraper already extracted instead of blowing up the request.
"""

from functools import lru_cache

try:
    from newspaper import Article
    NEWSPAPER_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on optional dependency
    NEWSPAPER_AVAILABLE = False


@lru_cache(maxsize=256)
def _summarize_cached(url: str) -> str:
    article = Article(url)
    article.download()
    article.parse()
    try:
        article.nlp()
        if article.summary:
            return article.summary.strip()
    except Exception:
        pass
    # nlp() (sumy/nltk) failed but parse() worked -- fall back to the
    # article's own meta description, then the first couple sentences.
    if article.meta_description:
        return article.meta_description.strip()
    if article.text:
        return " ".join(article.text.strip().split()[:60])
    return ""


def summarize(url: str, fallback: str = "") -> str:
    """Return a short summary of the article at `url`, or `fallback`."""
    if not NEWSPAPER_AVAILABLE or not url:
        return fallback

    try:
        summary = _summarize_cached(url)
        return summary or fallback
    except Exception:
        return fallback
