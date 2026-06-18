# agent/rate_limiter.py
#
# Rate limiter for all 5 threat intel APIs.
#
# WHY THIS EXISTS:
#   Every free-tier API has quotas. Without this file, hitting the limit
#   causes a crash or a 429 error mid-conversation. This file:
#     1. Tracks how many calls we've made to each API
#     2. Waits the right amount of time if we're going too fast
#     3. Returns a graceful message instead of crashing if daily limit hit
#
# HOW IT WORKS:
#   Each API has a RateLimit config (max calls, per how many seconds).
#   Before every API call, we call check_and_wait(api_name).
#   It looks at the timestamp of recent calls and sleeps if needed.
#
# Free tier limits (as of 2026):
#   VirusTotal  : 4 requests/minute, 500/day
#   AbuseIPDB   : 1000 requests/day
#   NVD         : 50 requests/30 seconds
#   Shodan      : 100 query credits/month
#   OTX         : Unlimited (community platform)

import time
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Optional
import json
import os
from datetime import datetime, date

# ── Rate Limit Configuration ──────────────────────────────────────

@dataclass
class RateLimit:
    """
    Defines the rate limit for one API.
    
    calls_per_window: max number of calls allowed
    window_seconds:   in this many seconds
    daily_limit:      max calls per day (None = no daily limit)
    """
    calls_per_window: int
    window_seconds:   int
    daily_limit:      Optional[int] = None
    monthly_limit:    Optional[int] = None

# Real free-tier limits for each API
API_LIMITS = {
    "virustotal":  RateLimit(calls_per_window=4,  window_seconds=60,  daily_limit=500),
    "abuseipdb":  RateLimit(calls_per_window=100, window_seconds=60,  daily_limit=1000),
    "nvd":        RateLimit(calls_per_window=50,  window_seconds=30,  daily_limit=None),
    "shodan":     RateLimit(calls_per_window=1,   window_seconds=1,   monthly_limit=100),
    "otx":        RateLimit(calls_per_window=100, window_seconds=60,  daily_limit=None),
}

# ── Persistent Counter Storage ────────────────────────────────────
# We save daily/monthly counts to a JSON file so they persist
# across app restarts within the same day/month.

COUNTER_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".rate_limit_counters.json"
)

def _load_counters() -> dict:
    """Load persisted daily/monthly counters from disk."""
    if os.path.exists(COUNTER_FILE):
        try:
            with open(COUNTER_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _save_counters(counters: dict):
    """Save counters to disk."""
    try:
        with open(COUNTER_FILE, "w") as f:
            json.dump(counters, f, indent=2)
    except Exception:
        pass

# ── RateLimiter Class ─────────────────────────────────────────────

class RateLimiter:
    """
    Thread-safe rate limiter for multiple APIs.
    
    Usage:
        limiter = RateLimiter()
        
        # Before every API call:
        ok, msg = limiter.check_and_wait("virustotal")
        if not ok:
            return {"error": msg}  # daily limit hit
        
        # After every successful API call:
        limiter.record_call("virustotal")
    """

    def __init__(self):
        # Per-API sliding window of recent call timestamps
        self._windows: dict[str, deque] = {
            api: deque() for api in API_LIMITS
        }
        # Thread lock — prevents race conditions if multiple calls happen simultaneously
        self._lock = threading.Lock()
        # Load persisted counters
        self._counters = _load_counters()

    def _get_today(self) -> str:
        return date.today().isoformat()

    def _get_month(self) -> str:
        return date.today().strftime("%Y-%m")

    def _daily_count(self, api: str) -> int:
        today = self._get_today()
        return self._counters.get(f"{api}:daily:{today}", 0)

    def _monthly_count(self, api: str) -> int:
        month = self._get_month()
        return self._counters.get(f"{api}:monthly:{month}", 0)

    def _increment_counters(self, api: str):
        today   = self._get_today()
        month   = self._get_month()
        daily_key   = f"{api}:daily:{today}"
        monthly_key = f"{api}:monthly:{month}"
        self._counters[daily_key]   = self._counters.get(daily_key, 0) + 1
        self._counters[monthly_key] = self._counters.get(monthly_key, 0) + 1
        _save_counters(self._counters)

    def check_and_wait(self, api: str) -> tuple[bool, str]:
        """
        Check if we can make an API call right now.
        If we need to wait, this method SLEEPS for the right duration.
        Returns (True, "") if call is allowed.
        Returns (False, reason) if daily/monthly limit is exhausted.
        
        Call this BEFORE every API request.
        """
        with self._lock:
            limit = API_LIMITS.get(api)
            if not limit:
                return True, ""  # unknown API — don't block it

            # ── Check daily limit ─────────────────────────────────
            if limit.daily_limit is not None:
                daily = self._daily_count(api)
                if daily >= limit.daily_limit:
                    msg = (
                        f"{api} daily limit reached ({daily}/{limit.daily_limit}). "
                        f"Resets at midnight. Using cached data if available."
                    )
                    return False, msg

            # ── Check monthly limit (Shodan) ──────────────────────
            if limit.monthly_limit is not None:
                monthly = self._monthly_count(api)
                if monthly >= limit.monthly_limit:
                    msg = (
                        f"{api} monthly limit reached ({monthly}/{limit.monthly_limit}). "
                        f"Resets next month."
                    )
                    return False, msg

            # ── Sliding window rate limit ─────────────────────────
            window = self._windows[api]
            now = time.time()

            # Remove timestamps older than the window
            while window and (now - window[0]) > limit.window_seconds:
                window.popleft()

            # If window is full, sleep until oldest call expires
            if len(window) >= limit.calls_per_window:
                sleep_time = limit.window_seconds - (now - window[0]) + 0.1
                if sleep_time > 0:
                    # Release lock while sleeping so other APIs aren't blocked
                    self._lock.release()
                    time.sleep(sleep_time)
                    self._lock.acquire()
                    # Clean window again after sleep
                    now = time.time()
                    while window and (now - window[0]) > limit.window_seconds:
                        window.popleft()

            return True, ""

    def record_call(self, api: str):
        """
        Record that an API call was just made.
        Call this AFTER every successful API request.
        """
        with self._lock:
            self._windows[api].append(time.time())
            self._increment_counters(api)

    def get_status(self) -> dict:
        """
        Returns current usage status for all APIs.
        Used by the /status endpoint and Langfuse observability.
        """
        today = self._get_today()
        month = self._get_month()
        status = {}

        for api, limit in API_LIMITS.items():
            daily_used   = self._counters.get(f"{api}:daily:{today}", 0)
            monthly_used = self._counters.get(f"{api}:monthly:{month}", 0)

            info = {
                "window_limit":   limit.calls_per_window,
                "window_seconds": limit.window_seconds,
            }
            if limit.daily_limit:
                info["daily_used"]      = daily_used
                info["daily_limit"]     = limit.daily_limit
                info["daily_remaining"] = max(0, limit.daily_limit - daily_used)
            if limit.monthly_limit:
                info["monthly_used"]      = monthly_used
                info["monthly_limit"]     = limit.monthly_limit
                info["monthly_remaining"] = max(0, limit.monthly_limit - monthly_used)

            status[api] = info

        return status


# ── Singleton instance ────────────────────────────────────────────
# One shared instance across the entire app.
# Import this wherever you need rate limiting:
#   from agent.rate_limiter import limiter

limiter = RateLimiter()
