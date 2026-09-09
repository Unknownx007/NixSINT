"""
sources.py - NixSINT data sources
Pulls the live, community-maintained detection databases from two
respected OSINT projects and normalizes them into one internal schema:

  * Sherlock Project   (MIT license)            https://sherlockproject.xyz
  * WhatsMyName (WMN)  (CC BY-SA 4.0)            https://github.com/WebBreacher/WhatsMyName

Both projects publish *live* JSON files describing exactly how to tell
whether a username is claimed on a given site (status code, page text,
or redirect target) - this is what actually fixes false positives,
because a plain "404 = not found" check breaks on any site that
returns 200 for both claimed and unclaimed profiles.

Author: DEDSEC
"""

import json
import time
import copy
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Any

import aiohttp

SHERLOCK_URLS = [
    "https://data.sherlockproject.xyz",
    "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json",
]
WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"

CACHE_DIR = Path.home() / ".cache" / "nixsint"
CACHE_FILE = CACHE_DIR / "sites_cache.json"
CACHE_MAX_AGE = 60 * 60 * 24 * 3  # 3 days

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
}


@dataclass
class Site:
    name: str
    source: str  # "sherlock" | "wmn"
    display_url: str  # template, placeholder = {u}
    check_url: str  # template, placeholder = {u}
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    payload: Any = None  # dict (sherlock, raw {} placeholders) or str (wmn, {u} placeholder)
    nsfw: bool = False
    regex: Optional[str] = None  # sherlock only - skip site if username fails this
    strip_char: Optional[str] = None  # wmn only - char stripped from username before substitution
    protection: list = field(default_factory=list)  # e.g. ["cloudflare", "captcha"] - known anti-bot measures
    detect: dict = field(default_factory=dict)


def _domain_key(url_template: str) -> str:
    """Rough dedup key so the same site from both sources isn't checked twice."""
    from urllib.parse import urlparse

    netloc = urlparse(url_template.split("{u}")[0]).netloc.lower()
    return netloc.removeprefix("www.").removeprefix("api.")


def _normalize_sherlock(raw: dict) -> list[Site]:
    sites = []
    for name, entry in raw.items():
        if name.startswith("$") or not isinstance(entry, dict):
            continue
        url = entry.get("urlProbe") or entry.get("url", "")
        url = url.replace("{}", "{u}")
        display = entry.get("url", "").replace("{}", "{u}")
        error_type = entry.get("errorType")

        detect: dict = {"kind": error_type}
        if error_type == "status_code":
            detect["not_found_code"] = entry.get("errorCode", 404)
        elif error_type == "message":
            msg = entry.get("errorMsg", "")
            detect["not_found_strings"] = msg if isinstance(msg, list) else [msg]
        elif error_type == "response_url":
            detect["not_found_url"] = entry.get("errorUrl", "").replace("{}", "{u}")
        else:
            continue  # unknown detection method, skip entry

        sites.append(
            Site(
                name=name,
                source="sherlock",
                display_url=display,
                check_url=url,
                method=entry.get("request_method", "GET"),
                headers=entry.get("headers", {}) or {},
                payload=entry.get("request_payload"),
                nsfw=bool(entry.get("isNSFW", False)),
                regex=entry.get("regexCheck"),
                detect=detect,
            )
        )
    return sites


def _normalize_wmn(raw: dict) -> list[Site]:
    sites = []
    for entry in raw.get("sites", []):
        url = entry.get("uri_check", "").replace("{account}", "{u}")
        display = entry.get("uri_pretty", entry.get("uri_check", "")).replace("{account}", "{u}")
        post_body = entry.get("post_body")
        method = "POST" if post_body else "GET"
        payload = post_body.replace("{account}", "{u}") if post_body else None

        detect = {
            "kind": "wmn",
            "e_code": entry.get("e_code", 200),
            "e_string": entry.get("e_string", "") or "",
            "m_code": entry.get("m_code"),
            "m_string": entry.get("m_string", "") or "",
        }

        sites.append(
            Site(
                name=entry.get("name", "Unknown"),
                source="wmn",
                display_url=display,
                check_url=url,
                method=method,
                headers=entry.get("headers", {}) or {},
                payload=payload,
                nsfw=(entry.get("cat") == "xx NSFW xx"),
                strip_char=entry.get("strip_bad_char"),
                protection=entry.get("protection", []) or [],
                detect=detect,
            )
        )
    return sites


async def _fetch_json(session: aiohttp.ClientSession, urls: list[str]) -> Optional[dict]:
    for url in urls:
        try:
            async with session.get(url, headers=HEADERS, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    return await resp.json(content_type=None)
        except (aiohttp.ClientError, Exception):
            continue
    return None


def _dedupe(sites: list[Site]) -> list[Site]:
    seen: dict[str, Site] = {}
    for site in sites:
        key = _domain_key(site.check_url) or site.name.lower()
        # Prefer Sherlock's entry on collision - it's purpose-built to avoid false positives.
        if key not in seen or (seen[key].source != "sherlock" and site.source == "sherlock"):
            seen[key] = site
    return list(seen.values())


def _sites_to_cache(sites: list[Site]) -> dict:
    return {
        "fetched_at": time.time(),
        "sites": [
            {
                **vars(copy.copy(s)),
            }
            for s in sites
        ],
    }


def _cache_to_sites(data: dict) -> list[Site]:
    return [Site(**s) for s in data.get("sites", [])]


async def load_sites(force_refresh: bool = False) -> tuple[list[Site], str]:
    """
    Returns (sites, status_message).
    Tries live sources first; falls back to local cache if offline.
    """
    if not force_refresh and CACHE_FILE.exists():
        age = time.time() - CACHE_FILE.stat().st_mtime
        if age < CACHE_MAX_AGE:
            try:
                cached = json.loads(CACHE_FILE.read_text())
                return _cache_to_sites(cached), f"loaded {len(cached['sites'])} sites from local cache"
            except Exception:
                pass

    async with aiohttp.ClientSession() as session:
        sherlock_raw, wmn_raw = None, None
        try:
            sherlock_raw = await _fetch_json(session, SHERLOCK_URLS)
        except Exception:
            pass
        try:
            wmn_raw = await _fetch_json(session, [WMN_URL])
        except Exception:
            pass

    sites: list[Site] = []
    if sherlock_raw:
        sites += _normalize_sherlock(sherlock_raw)
    if wmn_raw:
        sites += _normalize_wmn(wmn_raw)

    if sites:
        sites = _dedupe(sites)
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(json.dumps(_sites_to_cache(sites)))
        except OSError:
            pass
        return sites, (
            f"fetched {len(sites)} unique sites live "
            f"(Sherlock: {'ok' if sherlock_raw else 'unreachable'}, "
            f"WhatsMyName: {'ok' if wmn_raw else 'unreachable'})"
        )

    # Total failure - try stale cache as last resort
    if CACHE_FILE.exists():
        try:
            cached = json.loads(CACHE_FILE.read_text())
            return _cache_to_sites(cached), f"offline - loaded {len(cached['sites'])} sites from stale cache"
        except Exception:
            pass

    return [], "no network and no cache available - cannot load site database"
