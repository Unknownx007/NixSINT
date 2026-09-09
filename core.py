"""
core.py - NixSINT scanning engine
Runs every check in sites.py concurrently against one username, tagging
each result with its confidence tier so the UI never mixes them.

Author: DEDSEC
"""

import asyncio
from dataclasses import dataclass
from typing import Optional

import aiohttp

from sites import SITE_CHECKS, LOW_CONFIDENCE_CHECKS

MAX_CONCURRENT_REQUESTS = 8


@dataclass
class SiteResult:
    name: str
    url: str
    exists: Optional[bool]  # True / False / None (unknown - never guessed)
    confidence: str = "high"  # "high" | "low"


async def _run_one(session, name, check_fn, username, semaphore, confidence) -> SiteResult:
    async with semaphore:
        try:
            result = await check_fn(session, username)
        except Exception:
            return SiteResult(name, "", None, confidence)
    return SiteResult(name, result.url, result.exists, confidence)


async def scan_username(username: str, on_result=None) -> list[SiteResult]:
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    results: list[SiteResult] = []

    async with aiohttp.ClientSession() as session:
        tasks = [
            asyncio.create_task(_run_one(session, name, fn, username, semaphore, "high"))
            for name, fn in SITE_CHECKS.items()
        ] + [
            asyncio.create_task(_run_one(session, name, fn, username, semaphore, "low"))
            for name, fn in LOW_CONFIDENCE_CHECKS.items()
        ]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            if on_result:
                on_result(result)

    return results
