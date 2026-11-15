import hmac
from typing import Annotated

from fastapi import Depends, Header, HTTPException

from app.core.config import Settings, get_settings


def require_key(x_api_key: Annotated[str, Header()] = "", cfg: Settings = Depends(get_settings)) -> None:
    if not hmac.compare_digest(x_api_key.encode(), cfg.api_key.encode()):
        raise HTTPException(401, "invalid API key")
