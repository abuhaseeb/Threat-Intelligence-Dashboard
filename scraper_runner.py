"""
Runs one of the 12 uploaded scraper scripts to completion and returns
the JSON it produced.

Design notes
------------
Every scraper in scrapers/ already follows the same shape: a handful of
module-level constants at the top of the file (TARGET_USERNAME,
NUMBER_OF_REPORTS, OUTPUT_FILE, ...) that are read by an async/sync
main() (or, for Cisco Talos, scrape_talos()) which does the scraping and
writes OUTPUT_FILE itself.

Rather than rewriting each 20-30KB script, this module:
  1. (re)imports the target module fresh, so state never leaks between
     requests,
  2. overwrites the constants the dashboard needs to control (search
     target, result limit, auth token, output path) via setattr(),
  3. calls the module's entrypoint and awaits it if it's a coroutine,
  4. reads back OUTPUT_FILE and returns it as a Python dict.

Because step 2 happens before step 3, and the scraper functions look up
these names as globals at call time, no changes to the original scraper
logic are required.

Each call blocks until the browser the scraper drives has closed and the
JSON file has been written -- there is no background job queue. That
matches the "scrape once, terminate, show the result" behaviour the
dashboard is built around.
"""

import asyncio
import importlib
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

from config import PLATFORMS

BASE_DIR = Path(__file__).parent
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)


class ScraperError(RuntimeError):
    """Raised when a scraper fails or produces no usable output."""


def _fresh_import(module_name: str):
    """Import (or re-import) a scraper module with a clean module state."""
    if module_name in sys.modules:
        del sys.modules[module_name]
    return importlib.import_module(module_name)


def _run_entry(mod, cfg):
    entry_fn = getattr(mod, cfg["entry"])
    if cfg.get("is_async"):
        return asyncio.run(entry_fn())
    return entry_fn()


def _run_generic(platform_key, cfg, target, auth_token, limit, out_path):
    mod = _fresh_import(cfg["module"])

    if target and cfg.get("target_attr"):
        setattr(mod, cfg["target_attr"], target)
        for attr, template in cfg.get("extra_attr_template", {}).items():
            setattr(mod, attr, template.format(target=target))

    if auth_token and cfg.get("needs_auth_token"):
        setattr(mod, cfg["auth_attr"], auth_token)

    if limit and cfg.get("limit_attr"):
        try:
            setattr(mod, cfg["limit_attr"], int(limit))
        except (TypeError, ValueError):
            pass

    # Every scraper writes wherever OUTPUT_FILE points -- redirect it into
    # this project's output/ folder so results are easy to find and export.
    setattr(mod, "OUTPUT_FILE", out_path)

    _run_entry(mod, cfg)

    if not out_path.exists():
        raise ScraperError(
            f"{platform_key} scraper finished but did not write {out_path.name}"
        )
    return json.loads(out_path.read_text(encoding="utf-8"))


def _run_mastodon(cfg, target, limit, out_path):
    mod = _fresh_import(cfg["module"])

    if target and "@" in target:
        account, instance = target.split("@", 1)
    elif target:
        account, instance = target, "infosec.exchange"
    else:
        account, instance = "malware_traffic", "infosec.exchange"

    limit = int(limit) if limit else cfg.get("default_limit", 10)

    posts = asyncio.run(
        mod.scrape_mastodon_profile(account.strip(), instance.strip(), limit)
    )

    output = {
        "source": "mastodon",
        "account": f"@{account}@{instance}",
        "scrape_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "post_count": len(posts),
        "posts": posts,
    }
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    return output


def run_platform(platform_key, target=None, auth_token=None, limit=None):
    """
    Run the scraper for `platform_key` to completion and return its
    parsed JSON output. Raises ScraperError / the scraper's own
    exception on failure -- callers should catch and surface these.
    """
    if platform_key not in PLATFORMS:
        raise ScraperError(f"Unknown platform '{platform_key}'")

    cfg = PLATFORMS[platform_key]
    out_path = OUTPUT_DIR / f"{platform_key}_latest.json"

    if platform_key == "mastodon":
        data = _run_mastodon(cfg, target, limit, out_path)
    else:
        data = _run_generic(platform_key, cfg, target, auth_token, limit, out_path)

    return data
