from __future__ import annotations

import asyncio
import contextlib
import json
import time
from dataclasses import dataclass
from typing import Any

from aiohttp import WSMsgType, web

from .client import CDPClient, TargetSession
from .log import info


def normalize_url(url: str | None) -> str:
    value = (url or "").strip()
    if not value:
        return "about:blank"
    if "://" not in value and not value.startswith("about:"):
        return "https://" + value
    return value


def normalize_browser_socks(proxy: str | None) -> str | None:
    if proxy and proxy.lower().startswith("socks5h://"):
        return "socks5://" + proxy[len("socks5h://") :]
    return proxy


@dataclass(slots=True)
class RemoteBrowserOptions:
    cdp_endpoint: str
    listen_host: str
    listen_port: int
    socks: str | None = None
    browser_socks: str | None = None
    start_url: str = "about:blank"
    mode: str = "offscreen"
    width: int = 1440
    height: int = 900
    quality: int = 70
    every_nth_frame: int = 1
    offscreen_left: int = -2400
    offscreen_top: int = -1200
    close_target: bool = True
    import_cookies: bool = True


class RemoteBrowserServer:
    def __init__(self, options: RemoteBrowserOptions):
        self.options = options
        self.cdp: CDPClient | None = None
        self.session: TargetSession | None = None
        self.target_id: str | None = None
        self.browser_context_id: str | None = None
        self.window_id: int | None = None
        self._closed = asyncio.Event()
        self._clients: set[web.WebSocketResponse] = set()
        self._screencast_task: asyncio.Task | None = None
        self._state_task: asyncio.Task | None = None
        self._last_frame: dict[str, Any] | None = None
        self._last_state: dict[str, Any] | None = None
        self._started_at = time.time()

    async def start(self) -> None:
        if self.options.mode not in {"offscreen", "foreground", "background"}:
            raise ValueError("--mode must be offscreen, foreground, or background")

        self.cdp = await CDPClient.connect(self.options.cdp_endpoint, self.options.socks)
        await self._create_target()
        await self._enable_target()
        self._screencast_task = asyncio.create_task(self._screencast_loop())
        self._state_task = asyncio.create_task(self._state_loop())

    async def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        for task in (self._screencast_task, self._state_task):
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        for ws in list(self._clients):
            with contextlib.suppress(Exception):
                await ws.close()
        self._clients.clear()

        if self.session:
            with contextlib.suppress(Exception):
                await self.session.send("Page.stopScreencast")
            if self.cdp:
                with contextlib.suppress(Exception):
                    await self.cdp.detach(self.session)
            self.session = None

        if self.cdp:
            if self.target_id and self.options.close_target:
                with contextlib.suppress(Exception):
                    await self.cdp.close_target(self.target_id)
            if self.browser_context_id:
                with contextlib.suppress(Exception):
                    await self.cdp.dispose_browser_context(self.browser_context_id)
            await self.cdp.close()
            self.cdp = None

    async def wait_closed(self) -> None:
        await self._closed.wait()

    async def _create_target(self) -> None:
        assert self.cdp is not None
        effective_browser_socks = normalize_browser_socks(self.options.browser_socks)
        if effective_browser_socks:
            self.browser_context_id = await self.cdp.create_browser_context(
                proxy_server=effective_browser_socks,
                dispose_on_detach=False,
            )
            if self.options.import_cookies:
                cookies = await self.cdp.get_cookies()
                await self.cdp.set_cookies(cookies, browser_context_id=self.browser_context_id)
                info("imported {} cookies into proxied browser context", len(cookies))

        params: dict[str, Any] = {"url": "about:blank"}
        if self.browser_context_id:
            params["browserContextId"] = self.browser_context_id
        if self.options.mode in {"offscreen", "foreground"}:
            params.update(
                {
                    "newWindow": True,
                    "width": self.options.width,
                    "height": self.options.height,
                    "background": self.options.mode == "offscreen",
                }
            )
            if self.options.mode == "offscreen":
                params["left"] = self.options.offscreen_left
                params["top"] = self.options.offscreen_top
        elif self.options.mode == "background":
            params["background"] = True

        info("creating remote-browser target mode={} url={}", self.options.mode, self.options.start_url)
        result = await self.cdp.send("Target.createTarget", params)
        self.target_id = result["targetId"]
        self.session = await self.cdp.attach(self.target_id)

        if self.options.mode in {"offscreen", "foreground"}:
            with contextlib.suppress(Exception):
                window = await self.cdp.send("Browser.getWindowForTarget", {"targetId": self.target_id})
                self.window_id = int(window["windowId"])
                bounds: dict[str, Any] = {
                    "width": self.options.width,
                    "height": self.options.height,
                    "windowState": "normal",
                }
                if self.options.mode == "offscreen":
                    bounds["left"] = self.options.offscreen_left
                    bounds["top"] = self.options.offscreen_top
                await self.cdp.send("Browser.setWindowBounds", {"windowId": self.window_id, "bounds": bounds})

    async def _enable_target(self) -> None:
        assert self.session is not None
        await self.session.send("Page.enable")
        await self.session.send("Runtime.enable")
        with contextlib.suppress(Exception):
            await self.session.send("Emulation.setFocusEmulationEnabled", {"enabled": True})
        with contextlib.suppress(Exception):
            await self.session.send(
                "Emulation.setDeviceMetricsOverride",
                {
                    "width": self.options.width,
                    "height": self.options.height,
                    "deviceScaleFactor": 1,
                    "mobile": False,
                    "screenWidth": self.options.width,
                    "screenHeight": self.options.height,
                },
            )
        if self.options.mode == "foreground":
            with contextlib.suppress(Exception):
                await self.session.send("Page.bringToFront")
        await self.session.send("Page.navigate", {"url": normalize_url(self.options.start_url)})
        await self.session.send(
            "Page.startScreencast",
            {
                "format": "jpeg",
                "quality": self.options.quality,
                "maxWidth": self.options.width,
                "maxHeight": self.options.height,
                "everyNthFrame": self.options.every_nth_frame,
            },
        )

    async def _screencast_loop(self) -> None:
        assert self.cdp is not None
        assert self.session is not None
        while not self._closed.is_set():
            try:
                msg = await self.cdp.connection.wait_for_event("Page.screencastFrame", timeout=30)
            except asyncio.TimeoutError:
                info("waiting for screencast frames from target {}", self.target_id)
                continue
            if msg.get("sessionId") != self.session.session_id:
                continue
            params = msg.get("params", {})
            metadata = params.get("metadata", {})
            frame = {
                "type": "frame",
                "data": params.get("data", ""),
                "metadata": metadata,
                "frameSessionId": params.get("sessionId"),
                "targetId": self.target_id,
                "ts": time.time(),
            }
            self._last_frame = frame
            await self.session.send("Page.screencastFrameAck", {"sessionId": params.get("sessionId")})
            await self._broadcast(frame)

    async def _state_loop(self) -> None:
        while not self._closed.is_set():
            try:
                state = await self.current_state()
                self._last_state = state
                await self._broadcast({"type": "state", "state": state})
            except Exception as exc:
                info("state poll failed: {}", exc)
            await asyncio.sleep(1)

    async def current_state(self) -> dict[str, Any]:
        assert self.session is not None
        result = await self.session.evaluate(
            """
(() => ({
  url: location.href,
  title: document.title,
  readyState: document.readyState,
  width: window.innerWidth,
  height: window.innerHeight,
  scrollX: window.scrollX,
  scrollY: window.scrollY
}))()
"""
        )
        value = result.get("result", {}).get("value") or {}
        return {
            "url": value.get("url", ""),
            "title": value.get("title", ""),
            "readyState": value.get("readyState", ""),
            "width": int(value.get("width") or self.options.width),
            "height": int(value.get("height") or self.options.height),
            "scrollX": value.get("scrollX", 0),
            "scrollY": value.get("scrollY", 0),
            "mode": self.options.mode,
            "targetId": self.target_id,
            "browserContextId": self.browser_context_id,
            "uptimeSeconds": round(time.time() - self._started_at, 1),
        }

    async def handle_ws(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(max_msg_size=4 * 1024 * 1024, heartbeat=25)
        await ws.prepare(request)
        self._clients.add(ws)
        if self._last_state:
            await ws.send_str(json.dumps({"type": "state", "state": self._last_state}, separators=(",", ":")))
        if self._last_frame:
            await ws.send_str(json.dumps(self._last_frame, separators=(",", ":")))
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    await self.handle_client_message(ws, json.loads(msg.data))
                elif msg.type in {WSMsgType.ERROR, WSMsgType.CLOSE}:
                    break
        finally:
            self._clients.discard(ws)
        return ws

    async def handle_client_message(self, ws: web.WebSocketResponse, payload: dict[str, Any]) -> None:
        assert self.session is not None
        kind = payload.get("type")
        if kind == "navigate":
            await self.session.send("Page.navigate", {"url": normalize_url(payload.get("url"))})
        elif kind == "reload":
            await self.session.send("Page.reload", {"ignoreCache": bool(payload.get("ignoreCache", False))})
        elif kind == "history":
            await self._go_history(int(payload.get("delta", 0)))
        elif kind == "mouse":
            await self._dispatch_mouse(payload)
        elif kind == "scroll":
            await self._dom_scroll(float(payload.get("deltaX", 0)), float(payload.get("deltaY", 0)))
        elif kind == "key":
            await self._dispatch_key(payload)
        elif kind == "text":
            await self.session.send("Input.insertText", {"text": str(payload.get("text", ""))})
        elif kind == "copy":
            result = await self._copy_text()
            await ws.send_str(json.dumps({"type": "clipboard", **result}, separators=(",", ":")))
        elif kind == "close":
            await self.close()

    async def _go_history(self, delta: int) -> None:
        if delta == 0:
            return
        assert self.session is not None
        history = await self.session.send("Page.getNavigationHistory")
        entries = history.get("entries", [])
        target_index = int(history.get("currentIndex", 0)) + delta
        if 0 <= target_index < len(entries):
            await self.session.send("Page.navigateToHistoryEntry", {"entryId": entries[target_index]["id"]})

    async def _dispatch_mouse(self, payload: dict[str, Any]) -> None:
        assert self.session is not None
        params: dict[str, Any] = {
            "type": str(payload.get("event", "mouseMoved")),
            "x": float(payload.get("x", 0)),
            "y": float(payload.get("y", 0)),
            "button": str(payload.get("button", "none")),
            "modifiers": int(payload.get("modifiers", 0)),
        }
        if "clickCount" in payload:
            params["clickCount"] = int(payload.get("clickCount") or 1)
        if params["type"] == "mouseWheel":
            params["deltaX"] = float(payload.get("deltaX", 0))
            params["deltaY"] = float(payload.get("deltaY", 0))
        await self.session.send("Input.dispatchMouseEvent", params)

    async def _dom_scroll(self, delta_x: float, delta_y: float) -> None:
        assert self.session is not None
        await self.session.evaluate(
            f"""
(() => {{
  const deltaX = {delta_x};
  const deltaY = {delta_y};
  const x = Math.max(1, Math.floor(window.innerWidth / 2));
  const y = Math.max(1, Math.floor(window.innerHeight / 2));
  const canScroll = (node) => {{
    if (!node) return false;
    if (node === document.body || node === document.documentElement) {{
      return document.documentElement.scrollHeight > window.innerHeight ||
             document.documentElement.scrollWidth > window.innerWidth;
    }}
    const style = window.getComputedStyle(node);
    const yScrollable = ['auto', 'scroll', 'overlay'].includes(style.overflowY) &&
      node.scrollHeight > node.clientHeight;
    const xScrollable = ['auto', 'scroll', 'overlay'].includes(style.overflowX) &&
      node.scrollWidth > node.clientWidth;
    return yScrollable || xScrollable;
  }};
  let target = document.elementFromPoint(x, y);
  while (target && target !== document.body && target !== document.documentElement && !canScroll(target)) {{
    target = target.parentElement;
  }}
  if (!target || target === document.body || target === document.documentElement || !canScroll(target)) {{
    window.scrollBy(deltaX, deltaY);
    return {{ ok: true, target: 'window', scrollX: window.scrollX, scrollY: window.scrollY }};
  }}
  target.scrollLeft += deltaX;
  target.scrollTop += deltaY;
  return {{
    ok: true,
    target: target.tagName || 'element',
    scrollLeft: target.scrollLeft,
    scrollTop: target.scrollTop,
    windowScrollX: window.scrollX,
    windowScrollY: window.scrollY
  }};
}})()
"""
        )

    async def _dispatch_key(self, payload: dict[str, Any]) -> None:
        assert self.session is not None
        params: dict[str, Any] = {
            "type": str(payload.get("event", "keyDown")),
            "key": str(payload.get("key", "")),
            "code": str(payload.get("code", "")),
            "windowsVirtualKeyCode": int(payload.get("windowsVirtualKeyCode", 0)),
            "nativeVirtualKeyCode": int(payload.get("nativeVirtualKeyCode", 0)),
            "modifiers": int(payload.get("modifiers", 0)),
        }
        text = str(payload.get("text", ""))
        if text:
            params["text"] = text
            params["unmodifiedText"] = str(payload.get("unmodifiedText") or text)
        await self.session.send("Input.dispatchKeyEvent", params)

    async def _copy_text(self) -> dict[str, Any]:
        assert self.session is not None
        result = await self.session.evaluate(
            """
(() => {
  const selection = (window.getSelection && window.getSelection().toString()) || '';
  if (selection) return { ok: true, text: selection, source: 'selection' };
  const active = document.activeElement;
  if (active && typeof active.value === 'string') {
    const start = typeof active.selectionStart === 'number' ? active.selectionStart : 0;
    const end = typeof active.selectionEnd === 'number' ? active.selectionEnd : active.value.length;
    const text = end > start ? active.value.slice(start, end) : active.value;
    return { ok: true, text, source: 'active-value' };
  }
  if (active && active.isContentEditable) {
    return { ok: true, text: active.innerText || active.textContent || '', source: 'contenteditable' };
  }
  return { ok: false, text: '', source: '', reason: 'no selected or focused text' };
})()
"""
        )
        return result.get("result", {}).get("value") or {"ok": False, "text": "", "reason": "copy failed"}

    async def _broadcast(self, payload: dict[str, Any]) -> None:
        if not self._clients:
            return
        text = json.dumps(payload, separators=(",", ":"))
        stale: list[web.WebSocketResponse] = []
        for ws in self._clients:
            try:
                await ws.send_str(text)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self._clients.discard(ws)


VIEWER_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CDP Browser</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #111316;
      --bar: #191c20;
      --bar2: #20242a;
      --line: #353b44;
      --text: #e8edf2;
      --muted: #aeb8c4;
      --accent: #72d28b;
      --warn: #f5b85b;
      --danger: #ef6f6c;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      overflow: hidden;
      background: var(--bg);
      color: var(--text);
      font-family: Segoe UI, Arial, sans-serif;
    }
    .shell {
      display: grid;
      grid-template-rows: auto 1fr;
      height: 100vh;
    }
    .toolbar {
      display: grid;
      gap: 8px;
      padding: 8px;
      background: var(--bar);
      border-bottom: 1px solid var(--line);
    }
    .row {
      display: grid;
      grid-template-columns: auto 1fr auto;
      gap: 8px;
      align-items: center;
    }
    .nav {
      display: flex;
      gap: 6px;
      align-items: center;
    }
    .scroll-row {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      align-items: center;
    }
    .scroll-row button {
      min-width: 104px;
    }
    button, input {
      height: 34px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--bar2);
      color: var(--text);
      font: inherit;
    }
    button {
      min-width: 40px;
      padding: 0 10px;
      cursor: pointer;
    }
    button:hover, button:focus {
      border-color: var(--accent);
      outline: none;
    }
    button.danger:hover, button.danger:focus {
      border-color: var(--danger);
    }
    input {
      width: 100%;
      padding: 0 10px;
    }
    .status {
      display: flex;
      gap: 12px;
      min-width: 0;
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--warn);
      display: inline-block;
    }
    .dot.ready { background: var(--accent); }
    .viewport {
      min-height: 0;
      display: grid;
      place-items: center;
      background: #070809;
      overflow: hidden;
    }
    canvas {
      display: block;
      max-width: 100%;
      max-height: 100%;
      outline: none;
      background: #000;
      image-rendering: auto;
    }
    canvas:focus {
      box-shadow: inset 0 0 0 2px var(--accent);
    }
    @media (max-width: 720px) {
      .row {
        grid-template-columns: 1fr;
      }
      .nav {
        flex-wrap: wrap;
      }
      button {
        min-width: 54px;
      }
      .scroll-row button {
        flex: 1 1 120px;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <div class="toolbar">
      <form class="row" id="nav-form">
        <div class="nav">
          <button type="button" id="back" title="Back">Back</button>
          <button type="button" id="forward" title="Forward">Forward</button>
          <button type="button" id="reload" title="Reload">Reload</button>
        </div>
        <input id="address" autocomplete="off" spellcheck="false" value="about:blank">
        <div class="nav">
          <button type="submit" title="Navigate">Go</button>
          <button type="button" id="paste" title="Paste local clipboard">Paste</button>
          <button type="button" id="copy" title="Copy remote selection">Copy</button>
          <button type="button" class="danger" id="close" title="Close remote target">Close</button>
        </div>
      </form>
      <div class="scroll-row">
        <button type="button" data-scroll-y="-240" title="Scroll up">Scroll Up</button>
        <button type="button" data-scroll-y="-720" title="Page up">Page Up</button>
        <button type="button" data-scroll-y="720" title="Page down">Page Down</button>
        <button type="button" data-scroll-y="240" title="Scroll down">Scroll Down</button>
      </div>
      <div class="status">
        <span><span class="dot" id="dot"></span> <span id="conn">connecting</span></span>
        <span id="page-state"></span>
        <span id="target"></span>
      </div>
    </div>
    <div class="viewport">
      <canvas id="screen" tabindex="0"></canvas>
    </div>
  </div>
  <script>
    const canvas = document.getElementById('screen');
    const ctx = canvas.getContext('2d');
    const address = document.getElementById('address');
    const conn = document.getElementById('conn');
    const dot = document.getElementById('dot');
    const pageState = document.getElementById('page-state');
    const target = document.getElementById('target');
    let ws = null;
    let meta = { deviceWidth: 1440, deviceHeight: 900 };
    let remoteState = {};
    let lastMove = 0;

    function connect() {
      const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(`${scheme}//${location.host}/ws`);
      ws.onopen = () => {
        conn.textContent = 'connected';
        dot.classList.add('ready');
      };
      ws.onclose = () => {
        conn.textContent = 'disconnected';
        dot.classList.remove('ready');
        setTimeout(connect, 1000);
      };
      ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        if (message.type === 'frame') drawFrame(message);
        if (message.type === 'state') updateState(message.state || {});
        if (message.type === 'clipboard') copyRemote(message);
      };
    }

    function send(payload) {
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      ws.send(JSON.stringify(payload));
    }

    function drawFrame(message) {
      meta = message.metadata || meta;
      const width = Math.max(1, Math.round(meta.deviceWidth || remoteState.width || 1440));
      const height = Math.max(1, Math.round(meta.deviceHeight || remoteState.height || 900));
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
      }
      const image = new Image();
      image.onload = () => ctx.drawImage(image, 0, 0, canvas.width, canvas.height);
      image.src = `data:image/jpeg;base64,${message.data}`;
    }

    function updateState(state) {
      remoteState = state;
      if (document.activeElement !== address && state.url) address.value = state.url;
      document.title = state.title ? `${state.title} - CDP Browser` : 'CDP Browser';
      pageState.textContent = `${state.readyState || 'loading'} ${state.width || ''}x${state.height || ''}`;
      target.textContent = state.targetId ? `${state.mode || ''} ${String(state.targetId).slice(0, 12)}` : '';
    }

    function modifiers(event) {
      let value = 0;
      if (event.altKey) value |= 1;
      if (event.ctrlKey) value |= 2;
      if (event.metaKey) value |= 4;
      if (event.shiftKey) value |= 8;
      return value;
    }

    function buttonName(button) {
      if (button === 0) return 'left';
      if (button === 1) return 'middle';
      if (button === 2) return 'right';
      return 'none';
    }

    function pointer(event) {
      const rect = canvas.getBoundingClientRect();
      const width = canvas.width || meta.deviceWidth || 1440;
      const height = canvas.height || meta.deviceHeight || 900;
      return {
        x: Math.max(0, Math.min(width, (event.clientX - rect.left) * width / rect.width)),
        y: Math.max(0, Math.min(height, (event.clientY - rect.top) * height / rect.height)),
      };
    }

    function centerPoint() {
      const width = canvas.width || meta.deviceWidth || remoteState.width || 1440;
      const height = canvas.height || meta.deviceHeight || remoteState.height || 900;
      return { x: width / 2, y: height / 2 };
    }

    function sendScroll(deltaY) {
      send({
        type: 'scroll',
        deltaX: 0,
        deltaY,
      });
      canvas.focus();
    }

    function mouse(event, type) {
      const pos = pointer(event);
      send({
        type: 'mouse',
        event: type,
        x: pos.x,
        y: pos.y,
        button: type === 'mouseMoved' ? 'none' : buttonName(event.button),
        clickCount: event.detail || 1,
        modifiers: modifiers(event),
      });
    }

    document.getElementById('nav-form').addEventListener('submit', (event) => {
      event.preventDefault();
      send({ type: 'navigate', url: address.value });
      canvas.focus();
    });
    document.getElementById('back').addEventListener('click', () => send({ type: 'history', delta: -1 }));
    document.getElementById('forward').addEventListener('click', () => send({ type: 'history', delta: 1 }));
    document.getElementById('reload').addEventListener('click', () => send({ type: 'reload' }));
    document.getElementById('close').addEventListener('click', () => send({ type: 'close' }));
    document.getElementById('copy').addEventListener('click', () => send({ type: 'copy' }));
    document.querySelectorAll('[data-scroll-y]').forEach((button) => {
      button.addEventListener('click', () => sendScroll(Number(button.dataset.scrollY || '0')));
    });
    document.getElementById('paste').addEventListener('click', async () => {
      let text = '';
      if (navigator.clipboard && navigator.clipboard.readText) {
        text = await navigator.clipboard.readText();
      } else {
        text = window.prompt('Text to paste') || '';
      }
      send({ type: 'text', text });
      canvas.focus();
    });

    async function copyRemote(message) {
      if (!message.ok) {
        pageState.textContent = message.reason || 'copy failed';
        return;
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(message.text || '');
        pageState.textContent = `copied ${String(message.text || '').length} chars from ${message.source || 'remote'}`;
      }
    }

    canvas.addEventListener('contextmenu', (event) => event.preventDefault());
    canvas.addEventListener('mousedown', (event) => {
      canvas.focus();
      mouse(event, 'mousePressed');
      event.preventDefault();
    });
    canvas.addEventListener('mouseup', (event) => {
      mouse(event, 'mouseReleased');
      event.preventDefault();
    });
    canvas.addEventListener('mousemove', (event) => {
      const now = performance.now();
      if (now - lastMove < 25) return;
      lastMove = now;
      mouse(event, 'mouseMoved');
    });
    canvas.addEventListener('wheel', (event) => {
      const pos = pointer(event);
      send({
        type: 'mouse',
        event: 'mouseWheel',
        x: pos.x,
        y: pos.y,
        button: 'none',
        deltaX: event.deltaX,
        deltaY: event.deltaY,
        modifiers: modifiers(event),
      });
      event.preventDefault();
    }, { passive: false });
    canvas.addEventListener('keydown', (event) => {
      const printable = event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey;
      send({
        type: 'key',
        event: 'keyDown',
        key: event.key,
        code: event.code,
        text: printable ? event.key : '',
        unmodifiedText: printable ? event.key : '',
        windowsVirtualKeyCode: event.keyCode || 0,
        nativeVirtualKeyCode: event.keyCode || 0,
        modifiers: modifiers(event),
      });
      if (!event.metaKey) event.preventDefault();
    });
    canvas.addEventListener('keyup', (event) => {
      send({
        type: 'key',
        event: 'keyUp',
        key: event.key,
        code: event.code,
        windowsVirtualKeyCode: event.keyCode || 0,
        nativeVirtualKeyCode: event.keyCode || 0,
        modifiers: modifiers(event),
      });
      if (!event.metaKey) event.preventDefault();
    });
    canvas.addEventListener('paste', (event) => {
      const text = event.clipboardData ? event.clipboardData.getData('text') : '';
      if (text) send({ type: 'text', text });
      event.preventDefault();
    });

    connect();
  </script>
</body>
</html>
"""


async def health(request: web.Request) -> web.Response:
    server: RemoteBrowserServer = request.app["remote_browser"]
    return web.json_response(
        {
            "ok": not server._closed.is_set(),
            "targetId": server.target_id,
            "browserContextId": server.browser_context_id,
            "lastFrame": bool(server._last_frame),
            "state": server._last_state or {},
        }
    )


async def index(_: web.Request) -> web.Response:
    return web.Response(text=VIEWER_HTML, content_type="text/html")


async def websocket(request: web.Request) -> web.WebSocketResponse:
    server: RemoteBrowserServer = request.app["remote_browser"]
    return await server.handle_ws(request)


async def serve_remote_browser(options: RemoteBrowserOptions) -> None:
    server = RemoteBrowserServer(options)
    await server.start()
    app = web.Application()
    app["remote_browser"] = server
    app.add_routes(
        [
            web.get("/", index),
            web.get("/healthz", health),
            web.get("/ws", websocket),
        ]
    )
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, options.listen_host, options.listen_port)
    await site.start()
    print(f"CDP browser listening on http://{options.listen_host}:{options.listen_port}")
    print(f"Controlling {options.cdp_endpoint} target {str(server.target_id or '')[:12]} in {options.mode} mode")
    print("Press Ctrl+C here or Close in the viewer to stop.")
    try:
        await server.wait_closed()
    except asyncio.CancelledError:
        pass
    finally:
        await runner.cleanup()
        await server.close()
