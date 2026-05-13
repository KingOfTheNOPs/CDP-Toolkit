from __future__ import annotations

import asyncio
import re
from typing import Any

from .client import CDPClient
from .log import info


HOST_RE = re.compile(
    r"(?i)\b(?:(?:https?://)?(?:localhost|\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.[a-z]{2,})(?::\d{2,5})?(?:/[^\s]*)?)"
)
ACCOUNT_COUNT_RE = re.compile(r"(?i)^(\d+)\s+accounts?$")
EXTENSION_ID_RE = re.compile(r"^ID\s*([a-p]{32})$", re.I)
VERSION_RE = re.compile(r"^\d+(?:\.\d+)+(?:[._-]\d+)?$")

CONTROL_LINES = {
    "passwords",
    "settings",
    "autofill",
    "add",
    "delete",
    "edit",
    "copy",
    "search",
    "never saved",
    "saved passwords",
    "export passwords",
    "import passwords",
    "check passwords",
    "remove",
    "details",
    "errors",
    "extensions",
    "developer mode",
    "keyboard shortcuts",
    "open chrome web store",
    "open microsoft edge add-ons",
}


DEEP_SCRAPE_JS = r"""
(() => {
  const seenElements = new Set();
  const anchors = [];
  const elements = [];
  const lines = [];
  const lineSeen = new Set();

  function clean(value) {
    return String(value || "").replace(/\u00a0/g, " ").replace(/[ \t\r\f\v]+/g, " ").trim();
  }

  function pushLines(value) {
    for (const raw of String(value || "").split(/\n+/)) {
      const line = clean(raw);
      if (line && !lineSeen.has(line)) {
        lineSeen.add(line);
        lines.push(line);
      }
    }
  }

  function visit(node) {
    if (!node || seenElements.has(node)) return;
    seenElements.add(node);

    if (node.nodeType === Node.ELEMENT_NODE) {
      const el = node;
      const text = clean(el.innerText || el.textContent || "");
      const aria = clean(el.getAttribute && el.getAttribute("aria-label"));
      const title = clean(el.getAttribute && el.getAttribute("title"));
      const role = clean(el.getAttribute && el.getAttribute("role"));
      const id = clean(el.id || "");
      const cls = clean(el.className && String(el.className));
      const tag = clean(el.tagName || "").toLowerCase();
      const href = clean(el.href || el.getAttribute && el.getAttribute("href"));

      pushLines(el.innerText || el.textContent || "");
      if (text || aria || title || href) {
        const item = { tag, text, aria, title, role, id, className: cls, href };
        elements.push(item);
        if (tag === "a" || href) anchors.push(item);
      }

      if (el.shadowRoot) visit(el.shadowRoot);
    }

    const children = node.children ? Array.from(node.children) : [];
    for (const child of children) visit(child);
  }

  pushLines(document.body ? document.body.innerText : "");
  visit(document);

  return {
    url: location.href,
    title: document.title,
    readyState: document.readyState,
    lines,
    anchors,
    elements
  };
})()
"""

HISTORY_READY_JS = r"""
(() => {
  const app = document.querySelector('history-app');
  const list = app?.shadowRoot?.querySelector('history-list');
  return !!(list && Array.isArray(list.historyData_));
})()
"""

HISTORY_STATE_JS = r"""
(() => {
  const list = document.querySelector('history-app')?.shadowRoot?.querySelector('history-list');
  if (!list) return {count: 0, finished: false, querying: false, ready: false};
  return {
    count: list.historyData_?.length || 0,
    finished: !!list.queryResult?.info?.finished,
    querying: !!list.queryState?.querying,
    ready: true
  };
})()
"""

HISTORY_MORE_JS = r"""
(() => {
  const list = document.querySelector('history-app')?.shadowRoot?.querySelector('history-list');
  if (!list?.onScrollToBottom_) return false;
  list.onScrollToBottom_();
  return true;
})()
"""

HISTORY_DATA_JS = r"""
(() => {
  const list = document.querySelector('history-app')?.shadowRoot?.querySelector('history-list');
  return list?.historyData_ || [];
})()
"""

PASSWORD_READY_JS = r"""
(() => {
  const sec = document.querySelector('password-manager-app')
    ?.shadowRoot?.querySelector('passwords-section');
  return !!sec?.__data?.groups_;
})()
"""

PASSWORD_DATA_JS = r"""
(() => {
  const sec = document.querySelector('password-manager-app')
    ?.shadowRoot?.querySelector('passwords-section');
  const groups = sec?.__data?.groups_ || [];
  return groups.map(group => ({
    site: group.name || "",
    icon_url: group.iconUrl || "",
    entry_count: (group.entries || []).length,
    entries: (group.entries || []).map(entry => ({
      username: entry.username || "",
      id: entry.id,
      hidden: !!entry.hidden,
      stored_in: entry.storedIn || "",
      is_passkey: !!entry.isPasskey,
      change_password_url: entry.changePasswordUrl || "",
      affiliated_domains: (entry.affiliatedDomains || []).map(domain => ({
        name: domain.name || "",
        signon_realm: domain.signonRealm || "",
        url: domain.url || ""
      }))
    }))
  }));
})()
"""

EXTENSIONS_READY_JS = r"""
(() => {
  const mgr = document.querySelector('extensions-manager');
  return !!(mgr?.constructor?.name === 'ExtensionsManagerElement' && mgr.extensions_);
})()
"""

EXTENSIONS_DATA_JS = r"""
(() => {
  const mgr = document.querySelector('extensions-manager');
  const items = mgr?.extensions_ || [];
  return items.map(item => ({
    id: item.id || "",
    name: item.name || "",
    version: item.version || "",
    description: item.description || "",
    state: item.state || "",
    type: item.type || "",
    location: item.location || "",
    pinned_to_toolbar: item.pinnedToToolbar,
    incognito_enabled: item.incognitoAccess?.isActive,
    file_access_enabled: item.fileAccess?.isActive,
    homepage: item.homePage?.url || "",
    update_url: item.updateUrl || "",
    options_url: item.optionsPage?.url || "",
    permissions: (item.permissions?.simplePermissions || []).map(perm => perm.message || ""),
    host_permissions: (item.permissions?.runtimeHostPermissions?.hosts || []).map(host => host.host || ""),
    views: (item.views || []).map(view => ({
      type: view.type || "",
      url: view.url || "",
      incognito: !!view.incognito
    }))
  }));
})()
"""

BOOKMARKS_READY_JS = r"""
(() => typeof chrome !== 'undefined' && !!chrome.bookmarks && typeof chrome.bookmarks.getTree === 'function')()
"""

BOOKMARKS_DATA_JS = r"""
chrome.bookmarks.getTree()
"""


def product_prefix(product: str | None) -> str:
    product_l = (product or "").lower()
    return "edge" if "edg" in product_l or "edge" in product_l else "chrome"


def history_urls(product: str | None) -> list[str]:
    prefix = product_prefix(product)
    if prefix == "edge":
        return ["edge://history/all", "chrome://history/"]
    return ["chrome://history/", "edge://history/all"]


def extension_urls(product: str | None) -> list[str]:
    prefix = product_prefix(product)
    if prefix == "edge":
        return ["edge://extensions/", "chrome://extensions/"]
    return ["chrome://extensions/", "edge://extensions/"]


def password_urls(product: str | None) -> list[str]:
    prefix = product_prefix(product)
    if prefix == "edge":
        return [
            "edge://settings/autofill/passwords",
            "edge://password-manager/passwords",
            "chrome://password-manager/passwords",
            "chrome://settings/passwords",
        ]
    return [
        "chrome://password-manager/passwords",
        "chrome://settings/passwords",
        "edge://settings/autofill/passwords",
        "edge://password-manager/passwords",
    ]


def bookmark_urls(product: str | None) -> list[str]:
    prefix = product_prefix(product)
    if prefix == "edge":
        return ["edge://favorites/", "edge://favorites", "chrome://bookmarks/"]
    return ["chrome://bookmarks/", "edge://favorites/", "edge://favorites"]


async def scrape_webui(
    cdp: CDPClient,
    urls: list[str],
    *,
    mode: str = "background",
    wait: float = 2.0,
) -> dict[str, Any]:
    last_error: Exception | None = None
    for url in urls:
        target_id: str | None = None
        session = None
        try:
            info(f"opening temporary WebUI target {url!r} ({mode})")
            target_id = await cdp.create_target(url, mode=mode)
            session = await cdp.attach(target_id)
            await session.send("Page.enable")
            await asyncio.sleep(wait)
            result = await session.evaluate(DEEP_SCRAPE_JS)
            value = result.get("result", {}).get("value") or {}
            if isinstance(value, dict):
                value["targetId"] = target_id
                value["requestedUrl"] = url
                return value
        except Exception as exc:  # noqa: BLE001 - try fallback internal URL.
            last_error = exc
            info(f"WebUI scrape failed for {url!r}: {exc}")
        finally:
            if session is not None:
                try:
                    await cdp.detach(session)
                except Exception:
                    pass
            if target_id is not None:
                try:
                    await cdp.close_target(target_id)
                except Exception:
                    pass
    if last_error is not None:
        raise last_error
    raise RuntimeError("no WebUI URLs supplied")


async def _eval_value(session, expression: str) -> Any:
    result = await session.evaluate(expression)
    remote_object = result.get("result", {})
    if remote_object.get("subtype") == "error":
        raise RuntimeError(f"evaluation returned error subtype: {remote_object}")
    if "exceptionDetails" in result:
        raise RuntimeError(str(result["exceptionDetails"]))
    return remote_object.get("value")


async def _wait_for_true(session, expression: str, *, attempts: int = 20, delay: float = 0.5) -> None:
    for _ in range(attempts):
        if await _eval_value(session, expression) is True:
            return
        await asyncio.sleep(delay)
    raise RuntimeError("WebUI model was not ready")


async def _run_in_webui_model(
    cdp: CDPClient,
    urls: list[str],
    action,
    *,
    mode: str = "background",
    wait: float = 0.5,
) -> Any:
    last_error: Exception | None = None
    for url in urls:
        target_id: str | None = None
        session = None
        try:
            info(f"opening temporary model target {url!r} ({mode})")
            target_id = await cdp.create_target(url, mode=mode)
            session = await cdp.attach(target_id)
            await session.send("Runtime.enable")
            await session.send("Page.enable")
            await asyncio.sleep(wait)
            return await action(session)
        except Exception as exc:  # noqa: BLE001 - try next internal URL or fallback path.
            last_error = exc
            info(f"WebUI model read failed for {url!r}: {exc}")
        finally:
            if session is not None:
                try:
                    await cdp.detach(session)
                except Exception:
                    pass
            if target_id is not None:
                try:
                    await cdp.close_target(target_id)
                except Exception:
                    pass
    if last_error is not None:
        raise last_error
    raise RuntimeError("no WebUI URLs supplied")


def _normalize_history_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": item.get("title") or item.get("pageTitle") or "",
        "url": item.get("url") or "",
        "domain": item.get("domain") or "",
        "time": item.get("time") or item.get("dateTimeOfDay") or "",
        "date": item.get("dateRelativeDay") or item.get("dateShort") or "",
        "starred": item.get("starred"),
        "source": "history-webui-model",
    }


def filter_history_items(
    items: list[dict[str, Any]],
    *,
    text: str | None,
    domain: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    query = (text or "").lower()
    domain_l = (domain or "").lower()
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    for raw in items:
        item = _normalize_history_item(raw)
        url = str(item.get("url") or "")
        title = str(item.get("title") or "")
        if not url:
            continue
        haystack = f"{title}\n{url}\n{item.get('domain') or ''}".lower()
        if query and query not in haystack:
            continue
        if domain_l and domain_l not in url.lower() and domain_l not in str(item.get("domain") or "").lower():
            continue
        if url in seen:
            continue
        seen.add(url)
        out.append(item)
        if len(out) >= limit:
            break
    return out


async def collect_history(
    cdp: CDPClient,
    *,
    text: str | None,
    domain: str | None,
    limit: int,
    mode: str = "background",
) -> list[dict[str, Any]]:
    async def action(session) -> list[dict[str, Any]]:
        await _wait_for_true(session, HISTORY_READY_JS, attempts=12)
        previous_count = -1
        for _ in range(50):
            state = await _eval_value(session, HISTORY_STATE_JS) or {}
            current_count = int(state.get("count") or 0)
            if state.get("finished") is True:
                break
            if current_count >= limit and not text and not domain:
                break
            if not state.get("querying"):
                if current_count == previous_count:
                    break
                previous_count = current_count
                await _eval_value(session, HISTORY_MORE_JS)
            await asyncio.sleep(0.5)
        items = await _eval_value(session, HISTORY_DATA_JS) or []
        return filter_history_items(items, text=text, domain=domain, limit=limit)

    if product_prefix(cdp.endpoint.product) == "edge":
        raw = await scrape_webui(cdp, history_urls(cdp.endpoint.product), mode=mode)
        return parse_history(raw, text, domain, limit)

    try:
        return await _run_in_webui_model(cdp, history_urls(cdp.endpoint.product), action, mode=mode)
    except Exception as exc:  # noqa: BLE001 - Edge WebUI fallback.
        info(f"falling back to generic history WebUI scrape: {exc}")
        raw = await scrape_webui(cdp, history_urls(cdp.endpoint.product), mode=mode)
        return parse_history(raw, text, domain, limit)


def _merge_live_extension_targets(
    extensions: list[dict[str, Any]],
    live_targets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    live_by_id: dict[str, list[dict[str, Any]]] = {}
    for target in live_targets:
        url = str(target.get("url") or "")
        match = re.search(r"chrome-extension://([a-p]{32})/", url)
        if match:
            live_by_id.setdefault(match.group(1), []).append(target)

    by_id = {str(item.get("id") or "").lower(): dict(item) for item in extensions if item.get("id")}
    for ext_id, targets in live_by_id.items():
        by_id.setdefault(
            ext_id,
            {
                "id": ext_id,
                "name": "",
                "version": "",
                "description": "",
                "state": "",
                "type": "",
                "location": "",
                "permissions": [],
                "host_permissions": [],
                "views": [],
            },
        )
        by_id[ext_id]["live_targets"] = targets
    for ext_id, item in by_id.items():
        item.setdefault("live_targets", live_by_id.get(ext_id, []))
    return list(by_id.values())


async def collect_extensions(cdp: CDPClient, *, mode: str = "hidden") -> list[dict[str, Any]]:
    live_targets = await cdp.targets(include_non_pages=True)

    if product_prefix(cdp.endpoint.product) == "edge":
        raw = await scrape_webui(cdp, extension_urls(cdp.endpoint.product), mode=mode)
        return parse_extensions(raw, live_targets)

    async def action(session) -> list[dict[str, Any]]:
        await _wait_for_true(session, EXTENSIONS_READY_JS, attempts=30)
        items = await _eval_value(session, EXTENSIONS_DATA_JS) or []
        return _merge_live_extension_targets(items, live_targets)

    try:
        return await _run_in_webui_model(cdp, extension_urls(cdp.endpoint.product), action, mode=mode)
    except Exception as exc:  # noqa: BLE001 - Edge WebUI fallback.
        info(f"falling back to generic extensions WebUI scrape: {exc}")
        raw = await scrape_webui(cdp, extension_urls(cdp.endpoint.product), mode=mode)
        return parse_extensions(raw, live_targets)


async def collect_password_sites(
    cdp: CDPClient,
    *,
    limit: int,
    mode: str = "visible",
) -> list[dict[str, Any]]:
    async def action(session) -> list[dict[str, Any]]:
        await _wait_for_true(session, PASSWORD_READY_JS, attempts=20)
        groups = await _eval_value(session, PASSWORD_DATA_JS) or []
        return groups[:limit]

    if product_prefix(cdp.endpoint.product) == "edge":
        raw = await scrape_webui(cdp, password_urls(cdp.endpoint.product), mode=mode)
        return parse_password_sites(raw, limit)

    try:
        return await _run_in_webui_model(cdp, password_urls(cdp.endpoint.product), action, mode=mode)
    except Exception as exc:  # noqa: BLE001 - WebUI DOM fallback.
        info(f"falling back to generic password WebUI scrape: {exc}")
        raw = await scrape_webui(cdp, password_urls(cdp.endpoint.product), mode=mode)
        return parse_password_sites(raw, limit)


def flatten_bookmarks(
    tree: list[dict[str, Any]],
    *,
    text: str | None,
    domain: str | None,
    limit: int,
    include_folders: bool,
) -> list[dict[str, Any]]:
    query = (text or "").lower()
    domain_l = (domain or "").lower()
    out: list[dict[str, Any]] = []

    def emit(item: dict[str, Any]) -> None:
        if len(out) < limit:
            out.append(item)

    def walk(node: dict[str, Any], path: list[str]) -> None:
        if len(out) >= limit:
            return

        title = str(node.get("title") or "")
        url = str(node.get("url") or "")
        node_type = "bookmark" if url else "folder"
        next_path = path if url or not title else [*path, title]
        display_path = "/".join(path if url else next_path)
        haystack = f"{title}\n{url}\n{display_path}".lower()

        if (
            (node_type == "bookmark" or include_folders)
            and (not query or query in haystack)
            and (not domain_l or domain_l in url.lower())
        ):
            item = {
                "type": node_type,
                "id": node.get("id"),
                "parentId": node.get("parentId"),
                "title": title,
                "url": url or None,
                "path": display_path,
                "dateAdded": node.get("dateAdded"),
                "dateGroupModified": node.get("dateGroupModified"),
                "source": "bookmarks-api",
            }
            emit(item)

        for child in node.get("children") or []:
            if isinstance(child, dict):
                walk(child, next_path)

    for root in tree:
        if isinstance(root, dict):
            walk(root, [])
    return out


async def collect_bookmarks(
    cdp: CDPClient,
    *,
    text: str | None,
    domain: str | None,
    limit: int,
    include_folders: bool,
    tree: bool,
    mode: str = "hidden",
) -> list[dict[str, Any]]:
    async def action(session):
        await _wait_for_true(session, BOOKMARKS_READY_JS, attempts=10)
        return await _eval_value(session, BOOKMARKS_DATA_JS) or []

    try:
        raw_tree = await _run_in_webui_model(cdp, bookmark_urls(cdp.endpoint.product), action, mode=mode)
        if tree:
            return raw_tree
        return flatten_bookmarks(raw_tree, text=text, domain=domain, limit=limit, include_folders=include_folders)
    except Exception as exc:  # noqa: BLE001 - WebUI DOM fallback.
        info(f"falling back to generic bookmarks WebUI scrape: {exc}")
        raw = await scrape_webui(cdp, bookmark_urls(cdp.endpoint.product), mode=mode)
        return parse_bookmarks(raw, text=text, domain=domain, limit=limit)

def parse_history(raw: dict[str, Any], text: str | None, domain: str | None, limit: int) -> list[dict[str, Any]]:
    query = (text or "").lower()
    domain_l = (domain or "").lower()
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []

    for anchor in raw.get("anchors", []):
        href = str(anchor.get("href") or "")
        title = str(anchor.get("text") or anchor.get("aria") or anchor.get("title") or "").strip()
        if not href.startswith(("http://", "https://")) or not title:
            continue
        haystack = f"{title}\n{href}".lower()
        if query and query not in haystack:
            continue
        if domain_l and domain_l not in href.lower():
            continue
        key = (href, title)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "title": title,
                "url": href,
                "source_url": raw.get("url"),
            }
        )
        if len(out) >= limit:
            break
    return out


def parse_extensions(raw: dict[str, Any], live_targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    lines = [str(line).strip() for line in raw.get("lines", []) if str(line).strip()]
    live_by_id: dict[str, list[dict[str, Any]]] = {}
    for target in live_targets:
        url = str(target.get("url") or "")
        match = re.search(r"chrome-extension://([a-p]{32})/", url)
        if match:
            live_by_id.setdefault(match.group(1), []).append(target)

    parsed: dict[str, dict[str, Any]] = {}
    for idx, line in enumerate(lines):
        match = EXTENSION_ID_RE.match(line)
        if not match:
            continue
        ext_id = match.group(1).lower()
        window = lines[max(0, idx - 8) : idx]
        version = None
        version_index = None
        for offset in range(len(window) - 1, -1, -1):
            if VERSION_RE.match(window[offset]):
                version = window[offset]
                version_index = max(0, idx - 8) + offset
                break

        name = None
        if version_index is not None:
            for candidate in reversed(lines[max(0, version_index - 4) : version_index]):
                if candidate.lower() not in CONTROL_LINES and candidate.lower() not in {"from store", "source"}:
                    name = candidate
                    break
        if not name:
            for candidate in reversed(window):
                candidate_l = candidate.lower()
                if candidate_l not in CONTROL_LINES and not VERSION_RE.match(candidate) and not candidate_l.startswith("id"):
                    name = candidate
                    break

        description = None
        if version_index is not None:
            desc_parts = [
                item
                for item in lines[version_index + 1 : idx]
                if item.lower() not in CONTROL_LINES and not item.lower().startswith("id")
            ]
            if desc_parts:
                description = " ".join(desc_parts)

        active_views = [
            item
            for item in lines[idx + 1 : min(len(lines), idx + 8)]
            if item.lower() in {"service worker", "no active views"} or item.startswith("chrome-extension://")
        ]

        parsed[ext_id] = {
            "id": ext_id,
            "name": name,
            "version": version,
            "description": description,
            "active_views": active_views,
            "live_targets": live_by_id.get(ext_id, []),
            "source_url": raw.get("url"),
        }

    for ext_id, targets in live_by_id.items():
        parsed.setdefault(
            ext_id,
            {
                "id": ext_id,
                "name": None,
                "version": None,
                "description": None,
                "active_views": [],
                "live_targets": targets,
                "source_url": "Target.getTargets",
            },
        )
    return list(parsed.values())


def parse_password_sites(raw: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    lines = [str(line).strip() for line in raw.get("lines", []) if str(line).strip()]
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    for idx, line in enumerate(lines):
        line_l = line.lower()
        if (
            line_l in CONTROL_LINES
            or line_l.startswith(("edge://", "chrome://", "--"))
            or (":" in line and line.endswith(";"))
        ):
            continue
        match = HOST_RE.search(line)
        if not match:
            continue
        site = match.group(0).rstrip(".,;)")
        if site.lower() in seen:
            continue
        username = None
        entry_count = None
        for neighbor in lines[idx + 1 : min(len(lines), idx + 5)]:
            neighbor_l = neighbor.lower()
            account_match = ACCOUNT_COUNT_RE.match(neighbor)
            if account_match:
                entry_count = int(account_match.group(1))
                continue
            if (
                neighbor_l in CONTROL_LINES
                or neighbor_l.startswith("--")
                or (":" in neighbor and neighbor.endswith(";"))
                or HOST_RE.search(neighbor)
            ):
                continue
            if "@" in neighbor or len(neighbor) <= 80:
                username = neighbor
                break
        seen.add(site.lower())
        out.append({"site": site, "username": username, "entry_count": entry_count, "source_url": raw.get("url")})
        if len(out) >= limit:
            break
    return out


def parse_bookmarks(
    raw: dict[str, Any],
    *,
    text: str | None,
    domain: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    query = (text or "").lower()
    domain_l = (domain or "").lower()
    seen: set[str] = set()
    out: list[dict[str, Any]] = []

    for anchor in raw.get("anchors", []):
        href = str(anchor.get("href") or "")
        title = str(anchor.get("text") or anchor.get("aria") or anchor.get("title") or "").strip()
        if not href.startswith(("http://", "https://")) or not title:
            continue
        haystack = f"{title}\n{href}".lower()
        if query and query not in haystack:
            continue
        if domain_l and domain_l not in href.lower():
            continue
        key = href.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "type": "bookmark",
                "id": None,
                "parentId": None,
                "title": title,
                "url": href,
                "path": None,
                "dateAdded": None,
                "dateGroupModified": None,
                "source": "bookmarks-webui-scrape",
                "source_url": raw.get("url"),
            }
        )
        if len(out) >= limit:
            break
    return out
