# NixSINT

An OSINT username reconnaissance tool by **DEDSEC**.

NixSINT takes a username and checks it against a **live, merged database
of 1000+ site definitions**, pulled at runtime from two respected,
community-maintained OSINT projects:

| Source | License | Sites | Detection style |
|---|---|---|---|
| [Sherlock Project](https://sherlockproject.xyz) | MIT | ~450 | status code / page text / redirect target, purpose-built to avoid false positives |
| [WhatsMyName (WMN)](https://github.com/WebBreacher/WhatsMyName) | CC BY-SA 4.0 | ~700+ | expected/missing HTTP code + page text pair per site |

Sites are deduplicated by domain (Sherlock's definition wins on overlap,
since it's specifically engineered against false positives). The merged,
deduplicated total is typically **900–1100+ unique sites** — the exact
count is printed each run, since both upstream projects add/remove sites
regularly.

## Why this fixes false positives

There were two layers of false-positive risk, and both are handled now:

1. **Wrong detection rule.** The first version guessed "404 = not found"
   for every site. That breaks badly: plenty of sites return HTTP 200
   for both claimed and unclaimed usernames, or bury the real signal in
   page text or a redirect target. Sherlock and WMN each ship the
   *actual, verified* detection rule per site (`status_code`, `message`,
   or `response_url` for Sherlock; expected/missing code+string pairs
   for WMN) — NixSINT applies those directly instead of guessing.

2. **Bot-block pages read as "found."** Even with the right rule, a
   scripted HTTP client gets served a Cloudflare/CAPTCHA/anti-bot
   interstitial by a lot of major sites instead of the real page. That
   interstitial is HTTP 200 and contains neither the site's "found" nor
   "not found" string — so "the error message isn't here" was
   misread as "the profile exists." `core.py` now scans every response
   for common challenge-page markers ("Just a moment...", "cf-chl",
   "captcha", "Access Denied", etc.) and, if one is present, downgrades
   what looked like a hit to **unverified** instead of reporting it as
   confirmed. Results print in two separate tables — *Confident hits*
   and *Unverified (blocked response)* — so you always know which is
   which instead of getting one undifferentiated list.

No lightweight scripted tool can solve a real JavaScript/CAPTCHA
challenge — that's true of Sherlock and WMN's own reference
implementations too. The fix here isn't pretending that limitation
doesn't exist; it's refusing to report through it as if it were a
confirmed result.

## Project layout

```
NixSINT/
├── main.py          # entry point: banner, live DB load, scan, output
├── core.py           # scanning engine - applies each site's real detection logic
├── sources.py         # fetches + normalizes Sherlock & WhatsMyName datasets, caches locally
├── banner.py          # DEDSEC banner + quotes
├── requirements.txt
└── README.md
```

There's no bundled `data.json` anymore — the site list is fetched live
on each run (and cached to `~/.cache/nixsint/sites_cache.json` for 3
days, so you're not re-downloading ~1500 site definitions every single
run, and so the tool still works offline once you've run it once).

## Setup (Arch Linux / any Linux)

```bash
git clone <your-repo-url> NixSINT
cd NixSINT
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

Or without a venv on Arch:
```bash
pip install -r requirements.txt --break-system-packages
python3 main.py
```

Optional flags:
```bash
python3 main.py someusername       # skip the interactive prompt
python3 main.py --refresh          # force re-download of the site database
```

## How it works

1. **`sources.py`** downloads `data.sherlockproject.xyz` (Sherlock's live
   data file) and `wmn-data.json` (WhatsMyName's live data file),
   normalizes both into one internal `Site` schema, dedupes by domain,
   and caches the result.
2. **`core.py`** fires a concurrent request per site (capped by a
   semaphore so you don't get rate-limited), and evaluates each response
   using *that site's own* detection rule:
   - Sherlock `status_code` → compare HTTP status to the known "not
     found" code.
   - Sherlock `message` → check whether a known "not found" string
     appears in the page body.
   - Sherlock `response_url` → check whether the final (post-redirect)
     URL matches the known "not found" redirect target.
   - WMN → compare the response against both an "expected" (code +
     string) and a "missing" (code + string) signature.
   - Sherlock's `regexCheck` is honored too: if your username doesn't
     match a site's allowed username format, that site is **skipped**
     rather than reported as an incorrect miss.
3. **`main.py`** renders a live progress bar and a results table of every
   platform where the username was found, tagging adult-content
   platforms (`18+`) so you know at a glance what you're clicking.

## Attribution

This tool is a *checker* built on top of two datasets it does not own:
- Sherlock Project — MIT License. https://github.com/sherlock-project/sherlock
- WhatsMyName — CC BY-SA 4.0, © Micah "WebBreacher" Hoffman and
  contributors. https://github.com/WebBreacher/WhatsMyName

If you redistribute NixSINT, keep this attribution section — WMN's
license requires it, and it's just good practice regardless.

## Notes

- Some sites actively block automated requests (Cloudflare challenges,
  bot detection) — these show as `error/skip` rather than a false
  positive/negative, since request failures are treated as "unknown,"
  never as "not found."
- Don't crank `MAX_CONCURRENT_REQUESTS` in `core.py` too high or scan
  the same targets in a tight loop — you'll get throttled or banned by
  some platforms.
- This tool only checks for the *existence* of public profiles. It does
  not scrape private data, bypass authentication, or access anything
  not publicly visible.

— DEDSEC
