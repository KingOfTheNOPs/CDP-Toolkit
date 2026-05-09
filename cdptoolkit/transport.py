from __future__ import annotations

import asyncio
import contextlib
import json
from collections import defaultdict
from typing import Any, Callable

import websockets

from .config import DEFAULT_TIMEOUT
from .log import info


class CDPError(RuntimeError):
    pass


class CDPConnection:
    def __init__(self, ws_url: str, proxy: str | None = None, timeout: float = DEFAULT_TIMEOUT):
        self.ws_url = ws_url
        self.proxy = proxy
        self.timeout = timeout
        self._ws = None
        self._next_id = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._events: dict[str, list[dict]] = defaultdict(list)
        self._event_waiters: dict[str, list[tuple[asyncio.Future, Callable[[dict], bool] | None]]] = defaultdict(list)
        self._subscribers: list[tuple[asyncio.Queue, str | None, str | None]] = []
        self._reader_task: asyncio.Task | None = None

    async def __aenter__(self) -> "CDPConnection":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def connect(self) -> None:
        kwargs: dict[str, Any] = {"max_size": None}
        if self.proxy:
            kwargs["proxy"] = self.proxy
        info("opening CDP websocket {}{}", self.ws_url, f" via {self.proxy}" if self.proxy else "")
        try:
            self._ws = await websockets.connect(self.ws_url, **kwargs)
        except ImportError as exc:
            if self.proxy:
                raise CDPError("SOCKS WebSocket support requires python-socks[asyncio]. Reinstall the package with its current dependencies.") from exc
            raise
        except TypeError as exc:
            if self.proxy:
                raise CDPError("Installed websockets package does not support proxy=. Upgrade websockets or omit --socks.") from exc
            raise
        info("CDP websocket connected")
        self._reader_task = asyncio.create_task(self._reader())

    async def close(self) -> None:
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None
        if self._ws:
            info("closing CDP websocket")
            await self._ws.close()
            self._ws = None
        for future in self._pending.values():
            if not future.done():
                future.cancel()
        self._pending.clear()

    async def _reader(self) -> None:
        assert self._ws is not None
        async for raw in self._ws:
            msg = json.loads(raw)
            msg_id = msg.get("id")
            if msg_id is not None and msg_id in self._pending:
                future = self._pending.pop(msg_id)
                if msg.get("error"):
                    err = msg["error"]
                    future.set_exception(CDPError(f"{err.get('message', 'CDP error')} ({err.get('code', 'unknown')})"))
                else:
                    future.set_result(msg.get("result", {}))
                continue
            method = msg.get("method")
            if method:
                if method != "Page.screencastFrame":
                    self._events[method].append(msg)
                    if len(self._events[method]) > 100:
                        del self._events[method][:-100]
                waiters = self._event_waiters.get(method, [])
                remaining = []
                for future, predicate in waiters:
                    if future.done():
                        continue
                    params = msg.get("params", {})
                    if predicate is None or predicate(params):
                        future.set_result(msg)
                    else:
                        remaining.append((future, predicate))
                self._event_waiters[method] = remaining
                for queue, session_id, subscriber_method in list(self._subscribers):
                    if session_id is not None and msg.get("sessionId") != session_id:
                        continue
                    if subscriber_method is not None and method != subscriber_method:
                        continue
                    try:
                        queue.put_nowait(msg)
                    except asyncio.QueueFull:
                        try:
                            queue.get_nowait()
                        except asyncio.QueueEmpty:
                            pass
                        with contextlib.suppress(asyncio.QueueFull):
                            queue.put_nowait(msg)

    async def send(self, method: str, params: dict | None = None, session_id: str | None = None, timeout: float | None = None) -> dict:
        if not self._ws:
            raise CDPError("CDP connection is not open")
        self._next_id += 1
        msg_id = self._next_id
        payload: dict[str, Any] = {"id": msg_id, "method": method, "params": params or {}}
        if session_id:
            payload["sessionId"] = session_id
        info("CDP -> {}{} id={}", method, f" session={session_id[:8]}" if session_id else "", msg_id)
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self._pending[msg_id] = future
        await self._ws.send(json.dumps(payload, separators=(",", ":")))
        try:
            result = await asyncio.wait_for(future, timeout or self.timeout)
            info("CDP <- {} id={}", method, msg_id)
            return result
        finally:
            self._pending.pop(msg_id, None)

    async def send_no_wait(self, method: str, params: dict | None = None, session_id: str | None = None) -> int:
        if not self._ws:
            raise CDPError("CDP connection is not open")
        self._next_id += 1
        msg_id = self._next_id
        payload: dict[str, Any] = {"id": msg_id, "method": method, "params": params or {}}
        if session_id:
            payload["sessionId"] = session_id
        info("CDP -> {}{} id={} no-wait", method, f" session={session_id[:8]}" if session_id else "", msg_id)
        await self._ws.send(json.dumps(payload, separators=(",", ":")))
        return msg_id

    async def wait_for_event(
        self,
        method: str,
        predicate: Callable[[dict], bool] | None = None,
        timeout: float | None = None,
    ) -> dict:
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        waiter = (future, predicate)
        self._event_waiters[method].append(waiter)
        try:
            return await asyncio.wait_for(future, timeout or self.timeout)
        finally:
            self._event_waiters[method] = [
                existing for existing in self._event_waiters[method] if existing[0] is not future
            ]

    def subscribe_events(
        self,
        *,
        session_id: str | None = None,
        method: str | None = None,
        maxsize: int = 1000,
    ) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._subscribers.append((queue, session_id, method))
        return queue

    def unsubscribe_events(self, queue: asyncio.Queue) -> None:
        self._subscribers = [subscriber for subscriber in self._subscribers if subscriber[0] is not queue]
