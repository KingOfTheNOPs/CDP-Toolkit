from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin

import httpx

from .config import DEFAULT_TIMEOUT
from .log import info


@dataclass(frozen=True)
class BrowserEndpoint:
    cdp_endpoint: str
    web_socket_debugger_url: str
    product: str
    protocol_version: str
    user_agent: str
    raw: dict


def normalize_cdp_endpoint(cdp_endpoint: str) -> str:
    if cdp_endpoint.startswith("ws://") or cdp_endpoint.startswith("wss://"):
        return cdp_endpoint
    return cdp_endpoint.rstrip("/")


async def get_json(cdp_endpoint: str, path: str, proxy: str | None = None, timeout: float = DEFAULT_TIMEOUT) -> dict | list:
    base = normalize_cdp_endpoint(cdp_endpoint)
    if base.startswith("ws://") or base.startswith("wss://"):
        raise ValueError("HTTP JSON endpoints require --cdp-endpoint, not a WebSocket endpoint")
    url = urljoin(base + "/", path.lstrip("/"))
    info("GET {}{}", url, f" via {proxy}" if proxy else "")
    async with httpx.AsyncClient(proxy=proxy, timeout=timeout) as client:
        response = await client.get(url)
        response.raise_for_status()
        info("HTTP {} {}", response.status_code, url)
        return response.json()


async def get_version(cdp_endpoint: str, proxy: str | None = None) -> BrowserEndpoint:
    data = await get_json(cdp_endpoint, "/json/version", proxy=proxy)
    if not isinstance(data, dict):
        raise ValueError("/json/version did not return an object")
    ws = data.get("webSocketDebuggerUrl")
    if not ws:
        raise ValueError("/json/version did not include webSocketDebuggerUrl")
    info("resolved browser websocket {}", ws)
    return BrowserEndpoint(
        cdp_endpoint=normalize_cdp_endpoint(cdp_endpoint),
        web_socket_debugger_url=ws,
        product=data.get("Browser", ""),
        protocol_version=data.get("Protocol-Version", ""),
        user_agent=data.get("User-Agent", ""),
        raw=data,
    )


async def list_http_targets(cdp_endpoint: str, proxy: str | None = None) -> list[dict]:
    data = await get_json(cdp_endpoint, "/json/list", proxy=proxy)
    if isinstance(data, dict) and "value" in data:
        data = data["value"]
    if not isinstance(data, list):
        raise ValueError("/json/list did not return a list")
    return data


def endpoint_from_devtools_active_port(path: Path) -> str:
    info("reading DevToolsActivePort {}", path)
    lines = [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    if not lines:
        raise ValueError(f"{path} is empty")
    port = int(lines[0])
    return f"http://127.0.0.1:{port}"
