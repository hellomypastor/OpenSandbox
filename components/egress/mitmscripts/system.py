# Copyright 2026 Alibaba Group Holding Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# OpenSandbox egress system addon.
#
# Always loaded by the egress mitmproxy launcher. Stays transparent on the
# wire (does not add or alter headers that would reveal the proxy to peers).
#
# Behavior:
#   1. Forces streaming for SSE / chunked responses so each chunk is forwarded
#      immediately, bypassing the stream_large_bodies=1m buffer set in config.yaml
#      (which otherwise stalls LLM-style small-chunk streams).
#   2. Acts as Credential Proxy when the egress sidecar has an active
#      Credential Vault revision. The active revision is stored in the Go
#      sidecar process and read over an egress-container-private Unix socket.
#      Credential values are not logged. Response header values containing
#      credentials are always redacted; response body redaction is opt-in.
#   3. Implements SNI-aware ignore_hosts for transparent mode. mitmproxy's
#      built-in ignore_hosts check in transparent mode matches against the
#      destination IP first; the SNI hostname is only available inside the TLS
#      ClientHello, which arrives after the initial check. This addon re-checks
#      the same ignore_hosts patterns against the SNI hostname at the
#      tls_clienthello layer and sets ignore_connection=True when a match is
#      found, ensuring domain-based TLS pass-through works reliably.
#
# User-defined addons can be loaded alongside this script via
# OPENSANDBOX_EGRESS_MITMPROXY_SCRIPT (comma-separated for multiple scripts).
from __future__ import annotations

import http.client as http_client
import json
import os
import re
import socket
import time
from typing import Any

from mitmproxy import ctx, http
from mitmproxy.tls import ClientHelloData


CREDENTIAL_PROXY_SOCKET_ENV = "OPENSANDBOX_CREDENTIAL_PROXY_SOCKET"
DEFAULT_CREDENTIAL_PROXY_SOCKET = "/run/opensandbox/credential-proxy/active.sock"
ACTIVE_VAULT_PATH = "/credential-vault/_active"
VAULT_CACHE_TTL_SECONDS = 0.5
FLOW_REDACTIONS_KEY = "opensandbox_credential_redactions"
FLOW_REDACT_RESPONSE_BODY_KEY = "opensandbox_credential_redact_response_body"
REDACTED_BYTES = b"[REDACTED]"


class ActiveVault:
    def __init__(
        self,
        revision: int,
        bindings: list[dict[str, Any]],
        redactions: list[str],
    ) -> None:
        self.revision = revision
        self.bindings = bindings
        self.redactions = redactions


_vault_cache: ActiveVault | None = None
_vault_cache_loaded_at = 0.0


class UnixSocketHTTPConnection(http_client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float) -> None:
        super().__init__("credential-proxy", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


def tls_clienthello(data: ClientHelloData) -> None:
    """Re-check ignore_hosts patterns against SNI hostname.

    In transparent mode, mitmproxy checks ignore_hosts against the
    destination IP:port before the TLS handshake.  If the check fails at
    that stage (SNI not yet available), we get a second chance here with
    the actual hostname from the ClientHello SNI extension.
    """
    sni = data.client_hello.sni
    if not sni:
        return

    patterns = ctx.options.ignore_hosts
    if not patterns:
        return

    for pattern in patterns:
        try:
            if re.search(pattern, sni):
                data.ignore_connection = True
                return
        except re.error:
            pass


def _load_active_vault() -> ActiveVault | None:
    global _vault_cache, _vault_cache_loaded_at
    now = time.monotonic()
    if _vault_cache is not None and now - _vault_cache_loaded_at < VAULT_CACHE_TTL_SECONDS:
        return _vault_cache

    socket_path = (
        os.environ.get(CREDENTIAL_PROXY_SOCKET_ENV, "").strip()
        or DEFAULT_CREDENTIAL_PROXY_SOCKET
    )
    connection = UnixSocketHTTPConnection(socket_path, timeout=0.25)
    try:
        connection.request("GET", ACTIVE_VAULT_PATH)
        response = connection.getresponse()
        body = response.read()
        if response.status == 404:
            _vault_cache = None
            _vault_cache_loaded_at = now
            return None
        if response.status != 200:
            ctx.log.warn(
                f"credential proxy: active vault lookup failed with HTTP {response.status}"
            )
            _vault_cache = None
            _vault_cache_loaded_at = now
            return None
        payload = json.loads(body.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - mitm addon must not crash traffic handling
        ctx.log.warn(f"credential proxy: active vault lookup failed: {exc}")
        _vault_cache = None
        _vault_cache_loaded_at = now
        return None
    finally:
        connection.close()

    bindings = payload.get("bindings") or []
    redactions = [v for v in (payload.get("redactions") or []) if isinstance(v, str) and v]
    _vault_cache = ActiveVault(
        revision=int(payload.get("revision") or 0),
        bindings=bindings,
        redactions=redactions,
    )
    _vault_cache_loaded_at = now
    return _vault_cache


def _request_host(flow: http.HTTPFlow) -> str:
    host = flow.request.pretty_host or flow.request.host or ""
    return host.rstrip(".").lower()


def _request_port(flow: http.HTTPFlow) -> int:
    if flow.request.port:
        return int(flow.request.port)
    return 443 if flow.request.scheme == "https" else 80


def _request_path(flow: http.HTTPFlow) -> str:
    path = flow.request.path or "/"
    return path.split("?", 1)[0] or "/"


def _host_matches(host: str, pattern: str) -> tuple[bool, int]:
    pattern = pattern.rstrip(".").lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]
        apex = pattern[2:]
        return host.endswith(suffix) and host != apex, 1
    return host == pattern, 2


def _path_matches(path: str, pattern: str) -> bool:
    if pattern.endswith("*"):
        return path.startswith(pattern[:-1])
    return path == pattern


def _binding_matches(flow: http.HTTPFlow, binding: dict[str, Any]) -> tuple[bool, int]:
    match = binding.get("match") or {}
    scheme = (flow.request.scheme or "").lower()
    host = _request_host(flow)
    port = _request_port(flow)
    method = (flow.request.method or "").upper()
    path = _request_path(flow)

    if scheme not in (match.get("schemes") or ["https"]):
        return False, 0
    if port not in (match.get("ports") or [443]):
        return False, 0
    if method not in [m.upper() for m in (match.get("methods") or ["GET", "POST", "PUT", "PATCH", "DELETE"])]:
        return False, 0
    if not any(_path_matches(path, p) for p in (match.get("paths") or ["/*"])):
        return False, 0

    best_precedence = 0
    for pattern in match.get("hosts") or []:
        ok, precedence = _host_matches(host, pattern)
        if ok and precedence > best_precedence:
            best_precedence = precedence
    return best_precedence > 0, best_precedence


def _select_binding(flow: http.HTTPFlow, vault: ActiveVault) -> dict[str, Any] | None:
    matches: list[tuple[int, dict[str, Any]]] = []
    for binding in vault.bindings:
        ok, precedence = _binding_matches(flow, binding)
        if ok:
            matches.append((precedence, binding))
    if not matches:
        return None

    highest = max(precedence for precedence, _ in matches)
    selected = [binding for precedence, binding in matches if precedence == highest]
    if len(selected) != 1:
        flow.response = http.Response.make(
            403,
            b"credential binding ambiguous\n",
            {"content-type": "text/plain"},
        )
        ctx.log.warn(
            "credential proxy: ambiguous binding match for "
            f"{flow.request.method} {_request_host(flow)}{_request_path(flow)}"
        )
        return None
    return selected[0]


def request(flow: http.HTTPFlow) -> None:
    vault = _load_active_vault()
    if vault is None:
        return

    binding = _select_binding(flow, vault)
    if not binding:
        return

    injected_names: list[str] = []
    for header in binding.get("headers") or []:
        name = header.get("name")
        value = header.get("value")
        if not name or value is None:
            continue
        # mitmproxy Headers is case-insensitive; delete first to avoid duplicate
        # effective header names before setting the credentialed value.
        if name in flow.request.headers:
            del flow.request.headers[name]
        flow.request.headers[name] = value
        injected_names.append(name)

    if injected_names:
        flow.metadata[FLOW_REDACTIONS_KEY] = [
            value
            for value in (binding.get("redactions") or [])
            if isinstance(value, str) and value
        ]
        flow.metadata[FLOW_REDACT_RESPONSE_BODY_KEY] = bool(
            binding.get("redactResponseBody", False)
        )
        ctx.log.info(
            "credential proxy: injected binding="
            f"{binding.get('name')} revision={vault.revision} "
            f"host={_request_host(flow)} method={flow.request.method} "
            f"headers={','.join(injected_names)}"
        )


def responseheaders(flow: http.HTTPFlow) -> None:
    if flow.response is None:
        return
    _redact_response_headers(flow)
    content_type = flow.response.headers.get("content-type", "").lower()
    transfer_encoding = flow.response.headers.get("transfer-encoding", "").lower()
    requires_streaming = (
        "text/event-stream" in content_type
        or "chunked" in transfer_encoding
        or bool(flow.response.stream)
    )
    redactions = flow.metadata.get(FLOW_REDACTIONS_KEY, [])
    if not redactions or not _response_body_redaction_enabled(flow):
        if requires_streaming:
            flow.response.stream = True
        return

    if _response_has_no_body(flow):
        return

    content_encoding = flow.response.headers.get("content-encoding", "").lower().strip()
    compressed = bool(content_encoding and content_encoding != "identity")
    has_content_length = "content-length" in flow.response.headers
    if compressed:
        ctx.log.warn(
            "credential proxy: terminating compressed response because body "
            "redaction cannot safely bound decompressed size"
        )
        flow.kill()
        return

    # Install the transformer before mitmproxy can switch an unknown-length body
    # into streaming mode after stream_large_bodies is crossed. Redaction may
    # change the byte count, so the original fixed-length framing cannot survive.
    if has_content_length:
        del flow.response.headers["content-length"]
    flow.response.stream = _redacting_stream(redactions)


def _response_has_no_body(flow: http.HTTPFlow) -> bool:
    if flow.request.method.upper() == "HEAD":
        return True
    status_code = flow.response.status_code
    return 100 <= status_code < 200 or status_code in (204, 304)


def _response_body_redaction_enabled(flow: http.HTTPFlow) -> bool:
    return bool(flow.metadata.get(FLOW_REDACT_RESPONSE_BODY_KEY, False))


def _redact_response_headers(flow: http.HTTPFlow) -> None:
    redactions = flow.metadata.get(FLOW_REDACTIONS_KEY, [])
    if not redactions or flow.response is None:
        return
    for name, value in list(flow.response.headers.items()):
        redacted = _redact_text(value, redactions)
        if redacted != value:
            flow.response.headers[name] = redacted


def _redact_text(text: str, values: list[str]) -> str:
    out = text
    for value in _ordered_redactions(values):
        out = out.replace(value, "[REDACTED]")
    return out


def response(flow: http.HTTPFlow) -> None:
    if (
        flow.response is None
        or flow.response.stream
        or not _response_body_redaction_enabled(flow)
    ):
        return
    redactions = flow.metadata.get(FLOW_REDACTIONS_KEY, [])
    if not redactions:
        return
    try:
        content = flow.response.get_content(strict=True)
    except ValueError:
        flow.response = http.Response.make(
            502,
            b"credential proxy could not inspect upstream response\n",
            {"content-type": "text/plain"},
        )
        return
    if content is None:
        return
    redacted = _redact_bytes(content, redactions)
    if redacted != content:
        flow.response.set_content(redacted)


def _redact_bytes(content: bytes, values: list[str]) -> bytes:
    out = content
    for value in _ordered_redactions(values):
        out = out.replace(value.encode("utf-8"), REDACTED_BYTES)
    return out


def _ordered_redactions(values: list[str]) -> list[str]:
    return sorted({value for value in values if value}, key=len, reverse=True)


def _redacting_stream(values: list[str]):
    patterns = sorted(
        {value.encode("utf-8") for value in _ordered_redactions(values)},
        key=len,
        reverse=True,
    )
    if not patterns:
        return lambda chunk: chunk

    pending = b""
    max_pattern_len = len(patterns[0])

    def transform(chunk: bytes) -> bytes:
        nonlocal pending
        pending += chunk
        if not chunk:
            out = _redact_bytes(pending, values)
            pending = b""
            return out

        safe_limit = max(0, len(pending) - max_pattern_len + 1)
        cursor = 0
        out = bytearray()
        while cursor < safe_limit:
            match_index = -1
            match_pattern = b""
            for pattern in patterns:
                index = pending.find(pattern, cursor)
                if index >= 0 and (match_index < 0 or index < match_index):
                    match_index = index
                    match_pattern = pattern
            if match_index < 0 or match_index >= safe_limit:
                out.extend(pending[cursor:safe_limit])
                cursor = safe_limit
                break
            out.extend(pending[cursor:match_index])
            out.extend(REDACTED_BYTES)
            cursor = match_index + len(match_pattern)

        pending = pending[cursor:]
        return bytes(out)

    return transform
