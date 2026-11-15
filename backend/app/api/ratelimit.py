import time
from collections import defaultdict
from collections.abc import Callable

from fastapi import Depends, HTTPException, Request

from app.core.config import Settings, get_settings

# shortcut: in-memory fixed window per (bucket, client IP); resets on restart and is per process.
# Upgrade to Redis (or a reverse proxy limit) when running several workers.
_hits: dict[str, tuple[int, int]] = defaultdict(lambda: (0, 0))


def reset() -> None:
    _hits.clear()


def make_limiter(bucket: str, limit_of: Callable[[Settings], int]) -> Callable[..., None]:
    """Dependency factory: each bucket counts separately, so expensive endpoints can have a stricter limit."""

    def limiter(request: Request, cfg: Settings = Depends(get_settings)) -> None:
        minute = int(time.time() // 60)
        key = f"{bucket}:{request.client.host if request.client else 'unknown'}"
        window, count = _hits[key]
        count = count + 1 if window == minute else 1
        _hits[key] = (minute, count)
        if count > limit_of(cfg):
            raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": "60"})

    return limiter


rate_limit = make_limiter("events", lambda c: c.rate_limit_per_minute)
llm_rate_limit = make_limiter("llm", lambda c: c.llm_rate_limit_per_minute)
