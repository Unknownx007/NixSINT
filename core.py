"""
core.py - NixSINT scanning engine
Runs concurrent, correctly-detected username checks against the merged
Sherlock + WhatsMyName site database (see sources.py).

Key fix vs. earlier versions: many sites return HTTP 200 with a
Cloudflare/CAPTCHA/bot-block interstitial instead of the real page when
hit by a scripted client. That page contains neither the site's "found"
nor "not found" signal, so a naive checker misreads "the error string
isn't here" as "the profile exists" - a false positive. This version
detects those interstitials and downgrades the result to "uncertain"
instead of reporting it as a confident hit.

Author: DEDSEC
"""

import re
import json
import asyncio
from dataclasses import dataclass
from typing import Optional

import aiohttp

from sources import Site, HEADERS

MAX_CONCURRENT_REQUESTS = 30
REQUEST_TIMEOUT = 10  # seconds

# Substrings that show up on bot-block / challenge / CAPTCHA interstitials
# across common WAF and anti-bot vendors. If any of these appear in a
# response, we can't trust the site's own detection rule against it -
# we never had the real page.
BLOCK_MARKERS = [
    "just a moment",
    "checking your browser",
    "cf-browser-verification",
    "cf-chl",
    "attention required! | cloudflare",
    "enable javascript and cookies to continue",
    "please verify you are a human",
    "verify you are human",
    "captcha",
    "px-captcha",
    "perimeterx",
    "access denied",
    "request unsuccessful. incapsula",
    "ddos protection by",
    "sucuri website firewall",
    "distil_r_captcha",
    "you have been blocked",
    "unusual traffic from your computer",
    "bot detection",
]


@dataclass
class SiteResult:
    name: str
    url: str
    exists: Optional[bool]  # True / False / None (error, timeout, or skipped)
    uncertain: bool = False  # True = looked like a hit but response was a bot-block page
    nsfw: bool = False
    source: str = ""
    protected: bool = False  # site is known (via WMN metadata) to run anti-bot protection
    skipped: bool = False


def _sub(template: str, username: str) -> str:
    return template.replace("{u}", username)


def _substitute_payload(obj, username: str):
    """Recursively substitute Sherlock's '{}' placeholder inside a JSON payload."""
    if isinstance(obj, str):
        return obj.replace("{}", username)
    if isinstance(obj, dict):
        return {k: _substitute_payload(v, username) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_substitute_payload(v, username) for v in obj]
    return obj


def _looks_blocked(text: Optional[str]) -> bool:
    if not text:
        return False
    sample = text[:6000].lower()
    return any(marker in sample for marker in BLOCK_MARKERS)


def _evaluate(site: Site, status: int, final_url: str, text: Optional[str]) -> Optional[bool]:
    kind = site.detect.get("kind")

    if kind == "status_code":
        not_found_code = site.detect["not_found_code"]
        if status == not_found_code:
            return False
        if status == 200:
            return True
        return None  # 3xx left over, or 4xx/5xx that isn't the known code - inconclusive

    if kind == "message":
        if text is None:
            return None
        not_found_strings = site.detect["not_found_strings"]
        return not any(s in text for s in not_found_strings if s)

    if kind == "response_url":
        not_found_url = site.detect["not_found_url"].split("{u}")[0]
        if not_found_url and final_url.startswith(not_found_url):
            return False
        return True

    if kind == "wmn":
        e_code, e_string = site.detect["e_code"], site.detect["e_string"]
        m_code, m_string = site.detect["m_code"], site.detect["m_string"]
        text = text or ""
        matches_found = status == e_code and (not e_string or e_string in text)
        matches_missing = (m_code is not None and status == m_code) and (not m_string or m_string in text)
        if matches_found and not matches_missing:
            return True
        if matches_missing and not matches_found:
            return False
        if matches_found and matches_missing:
            return True  # ambiguous - lean toward the more specific "found" signal
        return None

    return None


async def _check_site(
    session: aiohttp.ClientSession,
    site: Site,
    username: str,
    semaphore: asyncio.Semaphore,
) -> SiteResult:
    # Sherlock's regexCheck: if the username doesn't fit this site's allowed
    # format, don't even bother requesting - it would only ever 404.
    if site.regex:
        try:
            if not re.fullmatch(site.regex, username):
                return SiteResult(
                    site.name, _sub(site.display_url, username), None,
                    nsfw=site.nsfw, source=site.source, skipped=True,
                )
        except re.error:
            pass

    resolved_username = username.replace(site.strip_char, "") if site.strip_char else username
    url = _sub(site.check_url, resolved_username)
    display_url = _sub(site.display_url, resolved_username)
    headers = {**HEADERS, **site.headers}

    data = None
    if site.method == "POST" and site.payload is not None:
        if site.source == "sherlock":
            data = json.dumps(_substitute_payload(site.payload, resolved_username))
            headers.setdefault("Content-Type", "application/json")
        else:  # wmn - payload is already a plain string template
            data = _sub(site.payload, resolved_username)

    exists: Optional[bool] = None
    uncertain = False

    async with semaphore:
        try:
            async with session.request(
                site.method,
                url,
                headers=headers,
                data=data,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                allow_redirects=True,
                ssl=False,
            ) as resp:
                # Always pull body text now (not just for message/wmn kinds) -
                # we need it to check for bot-block interstitials even on
                # status_code-type sites, since a Cloudflare challenge often
                # returns HTTP 200 and would otherwise be read as "found".
                text = await resp.text(errors="ignore")
                exists = _evaluate(site, resp.status, str(resp.url), text)

                if exists is True and _looks_blocked(text):
                    uncertain = True
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeDecodeError):
            exists = None

    return SiteResult(
        site.name, display_url, exists,
        uncertain=uncertain, nsfw=site.nsfw, source=site.source,
        protected=bool(site.protection),
    )


async def scan_username(username: str, sites: list[Site], on_result=None) -> list[SiteResult]:
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    results: list[SiteResult] = []

    async with aiohttp.ClientSession() as session:
        tasks = [asyncio.create_task(_check_site(session, site, username, semaphore)) for site in sites]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            if on_result:
                on_result(result)

    return results
