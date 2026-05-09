from __future__ import annotations

import copy
import re
from typing import Any


SECRET_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "token",
    "access_token",
    "refresh_token",
    "secret",
}

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE)


def _mask(value: Any) -> str:
    text = "" if value is None else str(value)
    return f"[REDACTED:{len(text)}]"


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        value = JWT_RE.sub("[REDACTED:jwt]", value)
        value = BEARER_RE.sub("[REDACTED:bearer]", value)
    return value


def redact_obj(obj: Any) -> Any:
    data = copy.deepcopy(obj)

    def walk(value: Any, key: str | None = None) -> Any:
        if key and key.lower() in SECRET_KEYS:
            return _mask(value)
        if isinstance(value, dict):
            return {k: walk(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(item) for item in value]
        return redact_value(value)

    return walk(data)


def redact_cookies(cookies: list[dict]) -> list[dict]:
    return [{**cookie, "value": _mask(cookie.get("value", ""))} for cookie in cookies]

