from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .discovery import BrowserEndpoint, get_version
from .log import info
from .transport import CDPConnection


@dataclass
class TargetSession:
    client: "CDPClient"
    target_id: str
    session_id: str

    async def send(self, method: str, params: dict | None = None) -> dict:
        return await self.client.send(method, params, session_id=self.session_id)

    async def evaluate(self, expression: str, *, return_by_value: bool = True, await_promise: bool = True) -> dict:
        return await self.send(
            "Runtime.evaluate",
            {
                "expression": expression,
                "returnByValue": return_by_value,
                "awaitPromise": await_promise,
                "userGesture": True,
            },
        )


class CDPClient:
    def __init__(self, endpoint: BrowserEndpoint, connection: CDPConnection):
        self.endpoint = endpoint
        self.connection = connection

    @classmethod
    async def connect(cls, cdp_endpoint: str, socks: str | None = None) -> "CDPClient":
        info("connecting to CDP endpoint {}", cdp_endpoint)
        endpoint = await get_version(cdp_endpoint, proxy=socks)
        conn = CDPConnection(endpoint.web_socket_debugger_url, proxy=socks)
        await conn.connect()
        info("connected to {}", endpoint.product)
        return cls(endpoint, conn)

    async def __aenter__(self) -> "CDPClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def close(self) -> None:
        info("closing browser client")
        await self.connection.close()

    async def send(self, method: str, params: dict | None = None, session_id: str | None = None) -> dict:
        return await self.connection.send(method, params, session_id=session_id)

    async def send_no_wait(self, method: str, params: dict | None = None, session_id: str | None = None) -> int:
        return await self.connection.send_no_wait(method, params, session_id=session_id)

    async def targets(self, include_non_pages: bool = False) -> list[dict]:
        result = await self.send("Target.getTargets")
        targets = result.get("targetInfos", [])
        info("received {} targets", len(targets))
        if include_non_pages:
            return targets
        pages = [target for target in targets if target.get("type") == "page"]
        info("filtered to {} page targets", len(pages))
        return pages

    async def attach(self, target_id: str) -> TargetSession:
        info("attaching to target {}", target_id)
        result = await self.send("Target.attachToTarget", {"targetId": target_id, "flatten": True})
        info("attached session {}", result["sessionId"])
        return TargetSession(self, target_id, result["sessionId"])

    async def attach_browser_target(self) -> TargetSession:
        info("attaching to browser target")
        result = await self.send("Target.attachToBrowserTarget")
        info("attached browser session {}", result["sessionId"])
        return TargetSession(self, "browser", result["sessionId"])

    async def detach(self, session: TargetSession) -> None:
        info("detaching session {}", session.session_id)
        await self.send("Target.detachFromTarget", {"sessionId": session.session_id})

    async def create_browser_context(self, *, proxy_server: str | None = None, dispose_on_detach: bool = True) -> str:
        params: dict[str, Any] = {"disposeOnDetach": dispose_on_detach}
        if proxy_server:
            params["proxyServer"] = proxy_server
        info("creating browser context{} disposeOnDetach={}", f" proxy={proxy_server}" if proxy_server else "", dispose_on_detach)
        result = await self.send("Target.createBrowserContext", params)
        info("created browser context {}", result["browserContextId"])
        return result["browserContextId"]

    async def browser_contexts(self) -> list[str]:
        result = await self.send("Target.getBrowserContexts")
        contexts = result.get("browserContextIds", [])
        info("received {} non-default browser contexts", len(contexts))
        return contexts

    async def dispose_browser_context(self, browser_context_id: str) -> None:
        info("disposing browser context {}", browser_context_id)
        await self.send("Target.disposeBrowserContext", {"browserContextId": browser_context_id})

    async def create_target(
        self,
        url: str,
        *,
        mode: str = "visible",
        browser_context_id: str | None = None,
        focus: bool | None = None,
    ) -> str:
        params: dict[str, Any] = {"url": url}
        if browser_context_id:
            params["browserContextId"] = browser_context_id
        if mode == "hidden":
            params["hidden"] = True
            params["background"] = True
        elif mode == "background":
            params["background"] = True
        if focus is not None:
            params["focus"] = focus
        info("creating target url={} mode={} context={}", url, mode, browser_context_id or "default")
        result = await self.send("Target.createTarget", params)
        info("created target {}", result["targetId"])
        return result["targetId"]

    async def close_target(self, target_id: str) -> bool:
        info("closing target {}", target_id)
        result = await self.send("Target.closeTarget", {"targetId": target_id})
        return bool(result.get("success", True))

    async def get_cookies(self, browser_context_id: str | None = None) -> list[dict]:
        params = {}
        if browser_context_id:
            params["browserContextId"] = browser_context_id
        result = await self.send("Storage.getCookies", params)
        cookies = result.get("cookies", [])
        info("received {} cookies", len(cookies))
        return cookies

    async def set_cookies(self, cookies: list[dict], browser_context_id: str | None = None) -> None:
        params: dict[str, Any] = {"cookies": cookies}
        if browser_context_id:
            params["browserContextId"] = browser_context_id
        info("setting {} cookies{}", len(cookies), f" in context {browser_context_id}" if browser_context_id else "")
        await self.send("Storage.setCookies", params)

    async def load_unpacked_extension(self, path: str, *, enable_in_incognito: bool = False) -> dict:
        session = await self.attach_browser_target()
        try:
            info("loading unpacked extension from {}", path)
            return await session.send(
                "Extensions.loadUnpacked",
                {"path": path, "enableInIncognito": enable_in_incognito},
            )
        finally:
            await self.detach(session)

    async def screenshot(self, target_id: str, out: Path, *, full: bool = False) -> Path:
        session = await self.attach(target_id)
        try:
            params: dict[str, Any] = {"format": "png"}
            if full:
                params["captureBeyondViewport"] = True
            result = await session.send("Page.captureScreenshot", params)
            out.write_bytes(base64.b64decode(result["data"]))
            info("wrote screenshot {}", out)
            return out
        finally:
            await self.detach(session)
