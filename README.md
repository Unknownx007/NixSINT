# NixSINT

An OSINT username checker by **DEDSEC**.

No third-party datasets. **29 hand-verified sites** split into two
honest tiers, plus one deliberate hard exclusion.

## The PyPI false positive - what was actually wrong, and the fix

A `200 OK` status alone never proves a profile is real - it can also be
a generic fallback page, a CDN/WAF edge case, or (as apparently
happened) something serving 200 where a browser gets a clean 404. The
fix: **every plain-page check now also requires the username to
literally appear in the response body** before it's reported as found.
A 200 with no trace of the username anywhere in the page is now
reported as `unknown`, never as a hit. This is checked in
`_verified_status_check()` in `sites.py`, and it's covered by an
automated test that reproduces the exact failure mode (200 + no
username in body → must return `None`, not `True`) before this was
shipped.

## Two tiers, shown separately, never mixed

- **Confident tier (20 sites)** - real documented APIs wherever one
  exists (GitHub, GitLab, Codeberg, Dev.to, Hacker News, Keybase,
  Lichess, Chess.com, Mastodon, Roblox, Steam, Reddit, TikTok's oEmbed),
  plus 7 plain-page checks with the content-verification fix above
  (PyPI, Kaggle, itch.io, Letterboxd, SourceHut, CodePen, Gravatar).
- **Low-confidence tier (9 sites)** - Instagram, Twitter/X, Facebook,
  LinkedIn, Spotify, Twitch, YouTube, Snapchat, Pinterest. None of these
  expose a clean unauthenticated API, so each uses the best unofficial
  trick available (Instagram's web-profile-info endpoint, Twitter's
  syndication widget endpoint, Twitch's public web GQL client, etc.).
  These can misfire, so results from this tier are shown in their own
  table and are never counted as "confident" - always verify manually.
- **Excluded entirely: Discord.** Not a confidence issue - there is no
  HTTP endpoint, official or unofficial, that exposes whether a Discord
  username exists without a bot token in a shared server with the
  target. Faking a check for it would just be guessing with extra
  steps, so it isn't included.

Run `python3 main.py --list-sites` to see the exact breakdown at any
time.

Every check, in both tiers, follows the same rule: only return
`True`/`False` on something concrete. Anything else - timeout,
rate-limit (429), unexpected status, a bot-block page - returns `None`
and is reported as unknown, not guessed.

## New look

The banner, progress bar, and all table styling now use a neon-green /
electric-cyan "terminal" theme instead of the original red. The
"NIXSINT" logo is built from a small letter-glyph table in `banner.py`
(rather than hand-typed ASCII art) so it can't end up misaligned.

## Project layout

```
NixSINT/
├── main.py       # entry point: banner, prompt, scan, three-tier results
├── core.py        # runs both tiers of checks concurrently, tags confidence
├── sites.py         # every check function, hand-written, content-verified
├── banner.py        # DEDSEC banner (programmatic glyphs) + quotes + theme colors
├── requirements.txt
└── README.md
```

## Setup (Arch Linux / any Linux)

```bash
git clone <your-repo-url> NixSINT
cd NixSINT
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

Or without a venv:
```bash
pip install -r requirements.txt --break-system-packages
python3 main.py
```

Usage:
```bash
python3 main.py someusername     # skip the interactive prompt
python3 main.py --list-sites     # show the full confident/low-confidence/excluded breakdown
```

## Extending the list

Add one function to `sites.py` and register it in `SITE_CHECKS` (if it
has a real API/endpoint) or `LOW_CONFIDENCE_CHECKS` (if it's a
best-effort page trick). If a plain-page check is the only option, run
it through `_verified_status_check()` so the username-in-body
requirement applies automatically. If there's genuinely no way to check
a site over HTTP without credentials, add it to `EXCLUDED_SITES` with
the reason instead of faking a check - that's how Discord was handled.

## Notes

- This tool only checks for the *existence* of public profiles. It does
  not scrape private data, bypass authentication, or access anything
  not publicly visible.
- Timeouts are set to 12s with one retry per request - raise
  `MAX_CONCURRENT_REQUESTS` in `core.py` if you're on a fast, unfiltered
  connection and want faster scans, or lower it if sites start timing
  out under load.
- Even a "confident" hit is worth a quick manual click before you rely
  on it for anything that matters.

— DEDSEC
