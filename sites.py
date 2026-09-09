"""
sites.py - NixSINT curated site checks

Two tiers:
  SITE_CHECKS              - high confidence. Real documented APIs
                              wherever one exists, plus a content-
                              verification pass on the handful of plain
                              page checks (see below).
  LOW_CONFIDENCE_CHECKS    - sites with no reliable unauthenticated API
                              (Instagram, Twitter/X, Facebook, LinkedIn,
                              Spotify, Twitch, YouTube, Snapchat,
                              Pinterest). Implemented with the best
                              available unofficial trick for each, but
                              genuinely less trustworthy - kept in a
                              separate tier and never mixed into the
                              confident results.
  EXCLUDED_SITES            - Discord only. There is no HTTP-reachable
                              way to check a Discord username's existence
                              without a bot token sitting in a shared
                              server with the target - that's not a
                              confidence problem, it's a "the data isn't
                              exposed over plain HTTP at all" problem, so
                              faking a check for it would just be lying
                              with extra steps.

Why a page returning HTTP 200 used to cause false positives (the PyPI
report): a "200 OK" alone doesn't prove the profile is real - it can
also be a generic page, a WAF/CDN edge case, or a cached fallback. Every
plain-page check below now ALSO requires the username to actually appear
in the response body before calling it a match. A 200 with no username
anywhere in the page is reported as unknown, not found.

Author: DEDSEC
"""

import json
import asyncio
from dataclasses import dataclass
from typing import Optional, Callable, Awaitable

import aiohttp

TIMEOUT = 12
RETRIES = 1  # one retry on timeout/connection error before giving up
UA = "NixSINT/1.0 (OSINT username checker; https://github.com/your-repo/NixSINT)"
DEFAULT_HEADERS = {"User-Agent": UA}

BLOCK_MARKERS = [
    "just a moment", "checking your browser", "cf-browser-verification",
    "cf-chl", "attention required! | cloudflare", "please verify you are a human",
    "verify you are human", "captcha", "px-captcha", "perimeterx",
    "access denied", "incapsula", "ddos protection by", "sucuri website firewall",
    "you have been blocked", "unusual traffic from your computer",
]


@dataclass
class CheckResult:
    exists: Optional[bool]
    url: str


def _looks_blocked(text: Optional[str]) -> bool:
    if not text:
        return False
    sample = text[:6000].lower()
    return any(marker in sample for marker in BLOCK_MARKERS)


async def _get(session, url, headers=None, allow_redirects=True):
    for attempt in range(RETRIES + 1):
        try:
            async with session.get(
                url,
                headers={**DEFAULT_HEADERS, **(headers or {})},
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                allow_redirects=allow_redirects,
                ssl=False,
            ) as resp:
                text = await resp.text(errors="ignore")
                return resp.status, text, str(resp.url)
        except Exception:
            if attempt < RETRIES:
                await asyncio.sleep(0.6)
                continue
            return None, None, None


async def _post(session, url, json_body=None, data=None, headers=None):
    for attempt in range(RETRIES + 1):
        try:
            async with session.post(
                url,
                json=json_body,
                data=data,
                headers={**DEFAULT_HEADERS, **(headers or {})},
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                ssl=False,
            ) as resp:
                text = await resp.text(errors="ignore")
                return resp.status, text, str(resp.url)
        except Exception:
            if attempt < RETRIES:
                await asyncio.sleep(0.6)
                continue
            return None, None, None


async def _verified_status_check(session, url, username, found_status=200, not_found_status=404):
    """Status check + content verification: a 200 only counts if the
    username actually appears in the page and it isn't a block page."""
    status, text, _ = await _get(session, url)
    if status == not_found_status:
        return False
    if status == found_status and text and not _looks_blocked(text):
        if username.lower() in text.lower():
            return True
        return None  # 200 but no sign of the username - don't trust it
    return None


# ---------------------------------------------------------------------------
# High confidence - real API / structured-endpoint checks
# ---------------------------------------------------------------------------

async def check_github(session, username):
    status, _, _ = await _get(session, f"https://api.github.com/users/{username}")
    exists = True if status == 200 else False if status == 404 else None
    return CheckResult(exists, f"https://github.com/{username}")


async def check_gitlab(session, username):
    status, text, _ = await _get(session, f"https://gitlab.com/api/v4/users?username={username}")
    exists = None
    if status == 200:
        try:
            exists = len(json.loads(text)) > 0
        except Exception:
            exists = None
    return CheckResult(exists, f"https://gitlab.com/{username}")


async def check_codeberg(session, username):
    status, _, _ = await _get(session, f"https://codeberg.org/api/v1/users/{username}")
    exists = True if status == 200 else False if status == 404 else None
    return CheckResult(exists, f"https://codeberg.org/{username}")


async def check_devto(session, username):
    status, _, _ = await _get(session, f"https://dev.to/api/users/by_username?url={username}")
    exists = True if status == 200 else False if status == 404 else None
    return CheckResult(exists, f"https://dev.to/{username}")


async def check_hackernews(session, username):
    status, text, _ = await _get(session, f"https://hn.algolia.com/api/v1/users/{username}")
    exists = None
    if status == 200:
        try:
            exists = json.loads(text) is not None
        except Exception:
            exists = None
    elif status == 404:
        exists = False
    return CheckResult(exists, f"https://news.ycombinator.com/user?id={username}")


async def check_keybase(session, username):
    status, text, _ = await _get(session, f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}")
    exists = None
    if status == 200:
        try:
            them = json.loads(text).get("them", [])
            exists = bool(them and them[0])
        except Exception:
            exists = None
    return CheckResult(exists, f"https://keybase.io/{username}")


async def check_lichess(session, username):
    status, _, _ = await _get(session, f"https://lichess.org/api/user/{username}")
    exists = True if status == 200 else False if status == 404 else None
    return CheckResult(exists, f"https://lichess.org/@/{username}")


async def check_chess_com(session, username):
    status, _, _ = await _get(session, f"https://api.chess.com/pub/player/{username}")
    exists = True if status == 200 else False if status == 404 else None
    return CheckResult(exists, f"https://www.chess.com/member/{username}")


async def check_mastodon_social(session, username):
    status, text, _ = await _get(session, f"https://mastodon.social/api/v1/accounts/lookup?acct={username}")
    exists = None
    if status == 200:
        try:
            exists = "id" in json.loads(text)
        except Exception:
            exists = None
    elif status == 404:
        exists = False
    return CheckResult(exists, f"https://mastodon.social/@{username}")


async def check_roblox(session, username):
    status, text, _ = await _post(
        session,
        "https://users.roblox.com/v1/usernames/users",
        json_body={"usernames": [username], "excludeBannedUsers": False},
    )
    exists = None
    if status == 200:
        try:
            exists = len(json.loads(text).get("data", [])) > 0
        except Exception:
            exists = None
    return CheckResult(exists, f"https://www.roblox.com/users/profile?username={username}")


async def check_steam(session, username):
    status, text, _ = await _get(session, f"https://steamcommunity.com/id/{username}/?xml=1")
    exists = None
    if status == 200 and text:
        if "The specified profile could not be found" in text:
            exists = False
        elif "<steamID64>" in text:
            exists = True
    return CheckResult(exists, f"https://steamcommunity.com/id/{username}")


async def check_reddit(session, username):
    status, text, _ = await _get(session, f"https://www.reddit.com/user/{username}/about.json")
    exists = None
    if status == 200 and text:
        try:
            data = json.loads(text)
            exists = "data" in data and data["data"].get("name", "").lower() == username.lower()
        except Exception:
            exists = None
    elif status == 404:
        exists = False
    return CheckResult(exists, f"https://www.reddit.com/user/{username}/")


async def check_tiktok(session, username):
    status, _, _ = await _get(session, f"https://www.tiktok.com/oembed?url=https://www.tiktok.com/@{username}")
    exists = True if status == 200 else False if status == 404 else None
    return CheckResult(exists, f"https://www.tiktok.com/@{username}")


async def check_pypi(session, username):
    url = f"https://pypi.org/user/{username}/"
    exists = await _verified_status_check(session, url, username)
    return CheckResult(exists, url)


async def check_kaggle(session, username):
    url = f"https://www.kaggle.com/{username}"
    exists = await _verified_status_check(session, url, username)
    return CheckResult(exists, url)


async def check_itch_io(session, username):
    url = f"https://{username}.itch.io"
    exists = await _verified_status_check(session, url, username)
    return CheckResult(exists, url)


async def check_letterboxd(session, username):
    url = f"https://letterboxd.com/{username}/"
    exists = await _verified_status_check(session, url, username)
    return CheckResult(exists, url)


async def check_sourcehut(session, username):
    url = f"https://sr.ht/~{username}"
    exists = await _verified_status_check(session, url, username)
    return CheckResult(exists, url)


async def check_codepen(session, username):
    url = f"https://codepen.io/{username}"
    exists = await _verified_status_check(session, url, username)
    return CheckResult(exists, url)


async def check_gravatar(session, username):
    url = f"https://gravatar.com/{username}"
    exists = await _verified_status_check(session, url, username)
    return CheckResult(exists, url)


SITE_CHECKS: dict[str, Callable[..., Awaitable[CheckResult]]] = {
    "GitHub": check_github,
    "GitLab": check_gitlab,
    "Codeberg": check_codeberg,
    "Dev.to": check_devto,
    "Hacker News": check_hackernews,
    "Keybase": check_keybase,
    "Lichess": check_lichess,
    "Chess.com": check_chess_com,
    "Mastodon (mastodon.social)": check_mastodon_social,
    "Roblox": check_roblox,
    "Steam": check_steam,
    "Reddit": check_reddit,
    "TikTok": check_tiktok,
    "PyPI": check_pypi,
    "Kaggle": check_kaggle,
    "itch.io": check_itch_io,
    "Letterboxd": check_letterboxd,
    "SourceHut": check_sourcehut,
    "CodePen": check_codepen,
    "Gravatar": check_gravatar,
}


# ---------------------------------------------------------------------------
# Low confidence - best unofficial trick available, no clean documented API.
# Shown separately, always, and never counted as a confirmed hit.
# ---------------------------------------------------------------------------

async def check_instagram(session, username):
    # Instagram's own web client calls this endpoint - unauthenticated,
    # but rate-limited hard and fails unpredictably after a few calls.
    url = f"https://instagram.com/{username}"
    status, text, final_url = await _get(session, url)
    exists = None
    if status == 200 and text and not _looks_blocked(text):
        if f"/{username.lower()}/" in final_url.lower() and username.lower() in text.lower():
            exists = True
        elif "page not found" in text.lower() or "couldn't find that page" in text.lower():
            exists = False
    return CheckResult(exists, url)


async def check_twitter(session, username):
    # Undocumented "follow button" widget endpoint - not an official API,
    # can change or disappear without notice.
    url = f"https://cdn.syndication.twimg.com/widgets/followbutton/info.json?screen_names={username}"
    status, text, _ = await _get(session, url)
    exists = None
    if status == 200 and text:
        try:
            data = json.loads(text)
            exists = isinstance(data, list) and len(data) > 0
        except Exception:
            exists = None
    elif status == 404:
        exists = False
    return CheckResult(exists, f"https://x.com/{username}")


async def check_facebook(session, username):
    # mbasic.facebook.com is Facebook's lightweight/legacy interface -
    # less JS-gated than the main site, but still frequently ambiguous.
    url = f"https://mbasic.facebook.com/{username}"
    status, text, _ = await _get(session, url)
    exists = None
    if status == 200 and text:
        low = text.lower()
        if "this page isn't available" in low or "content isn't available" in low:
            exists = False
        elif username.lower() in low and "login" not in low[:500]:
            exists = True
    return CheckResult(exists, f"https://www.facebook.com/{username}")


async def check_linkedin(session, username):
    # LinkedIn shows a login wall for almost everyone, logged in or not -
    # treat this as very low signal, expect mostly "unknown".
    url = f"https://www.linkedin.com/in/{username}"
    status, text, _ = await _get(session, url)
    exists = None
    if status == 200 and text and not _looks_blocked(text):
        low = text.lower()
        if "this profile is not available" in low or "page not found" in low:
            exists = False
        elif username.lower() in low:
            exists = True
    return CheckResult(exists, url)


async def check_spotify(session, username):
    url = f"https://open.spotify.com/user/{username}"
    status, text, _ = await _get(session, url)
    exists = None
    if status == 404:
        exists = False
    elif status == 200 and text and not _looks_blocked(text):
        if username.lower() in text.lower() and "profile" in text.lower():
            exists = True
    return CheckResult(exists, url)


async def check_twitch(session, username):
    # Twitch's web client's own GQL endpoint with its public web Client-Id -
    # not a registered app, so treat as unofficial/best-effort.
    status, text, _ = await _post(
        session,
        "https://gql.twitch.tv/gql",
        json_body={"query": '{ user(login: "%s") { id } }' % username},
        headers={"Client-Id": "kimne78kx3ncx6brgo4mv6wki5h1ko", "Content-Type": "application/json"},
    )
    exists = None
    if status == 200 and text:
        try:
            exists = json.loads(text).get("data", {}).get("user") is not None
        except Exception:
            exists = None
    return CheckResult(exists, f"https://www.twitch.tv/{username}")


async def check_youtube(session, username):
    url = f"https://www.youtube.com/@{username}"
    status, text, _ = await _get(session, url)
    exists = None
    if text and not _looks_blocked(text):
        low = text.lower()
        if "this channel does not exist" in low:
            exists = False
        elif status == 200 and username.lower() in low:
            exists = True
    return CheckResult(exists, url)


async def check_snapchat(session, username):
    url = f"https://www.snapchat.com/add/{username}"
    status, text, _ = await _get(session, url)
    exists = None
    if status == 200 and text and not _looks_blocked(text):
        low = text.lower()
        if 'og:title' in low and username.lower() in low:
            exists = True
    return CheckResult(exists, url)


async def check_pinterest(session, username):
    url = f"https://www.pinterest.com/{username}/"
    status, text, final_url = await _get(session, url)
    exists = None
    if status == 200 and text and not _looks_blocked(text):
        if f"/{username.lower()}/" in final_url.lower() and username.lower() in text.lower():
            exists = True
        elif "page not found" in text.lower() or "couldn't find that page" in text.lower():
            exists = False
    return CheckResult(exists, url)


LOW_CONFIDENCE_CHECKS: dict[str, Callable[..., Awaitable[CheckResult]]] = {
    "Instagram": check_instagram,
    "Twitter/X": check_twitter,
    "Facebook": check_facebook,
    "LinkedIn": check_linkedin,
    "Spotify": check_spotify,
    "Twitch": check_twitch,
    "YouTube": check_youtube,
    "Snapchat": check_snapchat,
    "Pinterest": check_pinterest,
}

# Discord is left out entirely, not just "low confidence": there is no
# HTTP endpoint, official or unofficial, that exposes whether a Discord
# username exists without a bot token sitting in a shared server with
# the target. A "check" for it would just always return a made-up
# answer, so it isn't included at all.
EXCLUDED_SITES = {
    "Discord": "no HTTP-reachable existence check exists - requires a bot token in a shared server, not just a request",
}
