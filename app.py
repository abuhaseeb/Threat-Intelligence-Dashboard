"""
Cyber Threat Intel Dashboard
============================
A thin Flask UI over the scraper scripts in scrapers/.

Three tabs:
  - Social Media (X, Reddit, Instagram, Mastodon)
  - Blogs (Sophos, Recorded Future, Intezer, CrowdStrike,
    Cisco Talos, Check Point, Malwarebytes, Palo Alto Unit 42)
  - Trending Malware (ANY.RUN, Malpedia, ThreatFox) -- each is a flat
    table of records rather than posts/articles, using whatever field
    names that source's scraper produces, so it's rendered and exported
    differently from the other two tabs (see the TRENDING branches below
    and renderTableResults() in static/js/app.js)

Each platform panel lets you (re)target the search (username / subreddit
/ account, where applicable), run the scraper, and view the extracted
posts/reports -- author, title/body, description (newspaper3k-summarized
for blogs), and IOCs -- then export that platform's latest results to
CSV or JSON.

Each scrape is a single blocking request: the browser automation runs to
completion and closes, THEN the page updates with results. There is no
background job / polling -- exactly one run per click.
"""

import csv
import io
import json
import traceback

from flask import Flask, render_template, request, jsonify, Response

from config import (
    PLATFORMS,
    SOCIAL,
    BLOG,
    TRENDING,
    platforms_by_category,
)
from scraper_runner import run_platform, ScraperError
from normalizer import normalize, CSV_FIELDS, to_csv_row, to_export_json, find_record_list

app = Flask(__name__)

# In-memory cache of the most recent result per platform, used by the
# CSV/JSON export endpoints. This is a single-user local tool, so no
# session/db bookkeeping is needed -- restart the app to clear it.
# Social/blog platforms cache {"target": ..., "rows": [...]}.
# Trending Malware platforms cache {"records": [...]} (already in the
# exact shape that platform's scraper emits -- see TRENDING branch below).
LAST_RESULTS = {}


@app.route("/")
def index():
    return render_template(
        "index.html",
        social_platforms=platforms_by_category(SOCIAL),
        blog_platforms=platforms_by_category(BLOG),
        trending_platforms=platforms_by_category(TRENDING),
    )


@app.route("/api/scrape/<platform_key>", methods=["POST"])
def api_scrape(platform_key):
    if platform_key not in PLATFORMS:
        return jsonify({"ok": False, "error": f"Unknown platform '{platform_key}'"}), 404

    cfg = PLATFORMS[platform_key]
    payload = request.get_json(silent=True) or {}

    target = (payload.get("target") or "").strip() or cfg.get("default_target")
    auth_token = (payload.get("auth_token") or "").strip() or None
    limit = payload.get("limit") or cfg.get("default_limit")

    if cfg.get("needs_auth_token") and not auth_token:
        return jsonify({
            "ok": False,
            "error": "This platform requires an auth token. Enter your X auth_token "
                     "above -- it's used only for this request and is never saved to disk.",
        }), 400

    try:
        raw_data = run_platform(
            platform_key, target=target, auth_token=auth_token, limit=limit
        )
    except ScraperError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502
    except Exception as exc:  # scraper-specific failures (site layout, network, auth, etc.)
        app.logger.error("Scrape failed for %s: %s", platform_key, traceback.format_exc())
        return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 502

    if cfg["category"] == TRENDING:
        # ANY.RUN / Malpedia / ThreatFox return their records either as
        # a bare list (Malpedia, ThreatFox) or a dict wrapping one
        # (ANY.RUN writes {"source": ..., "records": [...]}) -- either
        # way, unwrap it and use the records as-is. No post/IOC
        # normalization applies here; the table renders whatever field
        # names that scraper actually produced.
        records = find_record_list(raw_data)
        LAST_RESULTS[platform_key] = {"records": records}
        return jsonify({
            "ok": True,
            "platform": platform_key,
            "label": cfg["label"],
            "count": len(records),
            "records": records,
        })

    rows = normalize(platform_key, raw_data, target=target)
    LAST_RESULTS[platform_key] = {"target": target, "rows": rows}

    return jsonify({
        "ok": True,
        "platform": platform_key,
        "label": cfg["label"],
        "target": target,
        "count": len(rows),
        "rows": rows,
    })


@app.route("/api/export/<platform_key>/<fmt>")
def api_export(platform_key, fmt):
    if platform_key not in PLATFORMS:
        return jsonify({"ok": False, "error": f"Unknown platform '{platform_key}'"}), 404

    cfg = PLATFORMS[platform_key]
    cached = LAST_RESULTS.get(platform_key)
    if not cached:
        return jsonify({
            "ok": False,
            "error": "No scraped data for this platform yet -- run a scrape first.",
        }), 404

    filename_base = f"{platform_key}_export"

    if cfg["category"] == TRENDING:
        records = cached["records"]

        if fmt == "json":
            payload = json.dumps(records, indent=2, ensure_ascii=False)
            return Response(
                payload,
                mimetype="application/json",
                headers={"Content-Disposition": f"attachment; filename={filename_base}.json"},
            )

        if fmt == "csv":
            # Each Trending Malware source has its own field names, so the
            # CSV header is derived from the records themselves (union of
            # every key seen, in first-appearance order) rather than a
            # fixed column list -- this way "complete information" holds
            # for ANY.RUN, Malpedia, and ThreatFox alike without one
            # export format hiding fields the other two don't share.
            fieldnames = []
            for record in records:
                for key in record.keys():
                    if key not in fieldnames:
                        fieldnames.append(key)

            buffer = io.StringIO()
            writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for record in records:
                flat = {
                    k: (", ".join(v) if isinstance(v, list) else v)
                    for k, v in record.items()
                }
                writer.writerow(flat)
            return Response(
                buffer.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename={filename_base}.csv"},
            )

        return jsonify({"ok": False, "error": "fmt must be 'csv' or 'json'"}), 400

    rows = cached["rows"]

    if fmt == "json":
        payload = json.dumps(
            [to_export_json(row) for row in rows], indent=2, ensure_ascii=False
        )
        return Response(
            payload,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename_base}.json"},
        )

    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(to_csv_row(row))
        return Response(
            buffer.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename_base}.csv"},
        )

    return jsonify({"ok": False, "error": "fmt must be 'csv' or 'json'"}), 400


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
