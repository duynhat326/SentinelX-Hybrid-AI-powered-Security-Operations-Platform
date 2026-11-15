import time
from collections import defaultdict

from fastapi import Depends, HTTPException, Request

from app.core.config import Settings, get_settings

# shortcut: in-memory fixed window per client IP; resets on restart and is per process.
# Upgrade to Redis (or a reverse proxy limit) when running several workers.
_hits: dict[str, tuple[int, int]] = defaultdict(lambda: (0, 0))


def reset() -> None:
    _hits.clear()


def rate_limit(request: Request, cfg: Settings = Depends(get_settings)) -> None:
    minute = int(time.time() // 60)
    ip = request.client.host if request.client else "unknown"
    window, count = _hits[ip]
    count = count + 1 if window == minute else 1
    _hits[ip] = (minute, count)
    if count > cfg.rate_limit_per_minute:
        raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": "60"})
