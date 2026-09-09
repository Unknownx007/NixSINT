# NixSINT

An OSINT username checker by **DEDSEC**.

**NixSINT** is a OSINT tool which lets you search username many popular websites. If you're investigating a person of interest, verifying an online identity, or simply curious about your own digital footprint, this project powers the tools that make that possible.

**REMEMBER!! NOT EVERY AUTOMATED TOOLS ARE 100% CORRECT EVERYTIME, YOU SHOULD CHECK MANUALLY AS WELL**

*NixSINT* provides a pre-stored dataabase.
*if you want to expand the data based you can manually add more elements to DB according to given instructions below.*

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
git clone https://github.com/Unknownx007/NixSINT
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
