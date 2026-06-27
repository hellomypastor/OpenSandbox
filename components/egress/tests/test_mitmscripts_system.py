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

from __future__ import annotations

import importlib.util
import json
import os
import sys
import types
import unittest
from pathlib import Path
from typing import Any


class _Log:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def warn(self, message: str) -> None:
        self.messages.append(message)

    def info(self, message: str) -> None:
        self.messages.append(message)


class _Headers:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = dict(values)

    def get(self, name: str, default: str = "") -> str:
        for key, value in self._values.items():
            if key.lower() == name.lower():
                return value
        return default

    def items(self) -> list[tuple[str, str]]:
        return list(self._values.items())

    def __setitem__(self, name: str, value: str) -> None:
        self._values[name] = value

    def __contains__(self, name: str) -> bool:
        return any(key.lower() == name.lower() for key in self._values)

    def __delitem__(self, name: str) -> None:
        for key in list(self._values):
            if key.lower() == name.lower():
                del self._values[key]
                return


class _Request:
    def __init__(self) -> None:
        self.pretty_host = "code.example.com"
        self.host = "code.example.com"
        self.port = 443
        self.scheme = "https"
        self.method = "GET"
        self.path = "/api/v8/projects"
        self.headers = _Headers({})


class _Response:
    def __init__(self) -> None:
        self.headers = _Headers(
            {
                "content-type": "application/json",
                "x-token-echo": "secret-token",
            }
        )
        self.status_code = 200
        self.stream = False
        self.body = b"upstream body includes secret-token"
        self.set_text_called = False
        self.set_content_called = False

    def get_text(self, strict: bool = False) -> str:
        return self.body.decode("utf-8")

    def set_text(self, value: str) -> None:
        self.set_text_called = True
        self.body = value.encode("utf-8")

    def get_content(self, strict: bool = True) -> bytes:
        return self.body

    def set_content(self, value: bytes) -> None:
        self.set_content_called = True
        self.body = value


class _Flow:
    def __init__(self) -> None:
        self.request = _Request()
        self.response = _Response()
        self.metadata: dict[str, Any] = {}
        self.killed = False

    def kill(self) -> None:
        self.killed = True


def _load_system_module() -> Any:
    mitmproxy = types.ModuleType("mitmproxy")
    mitmproxy.ctx = types.SimpleNamespace(log=_Log(), options=types.SimpleNamespace(ignore_hosts=[]))
    mitmproxy.http = types.SimpleNamespace(HTTPFlow=object, Response=types.SimpleNamespace(make=lambda *args: None))
    mitmproxy_tls = types.ModuleType("mitmproxy.tls")
    mitmproxy_tls.ClientHelloData = object

    sys.modules["mitmproxy"] = mitmproxy
    sys.modules["mitmproxy.tls"] = mitmproxy_tls

    path = Path(__file__).parents[1] / "mitmscripts" / "system.py"
    spec = importlib.util.spec_from_file_location("opensandbox_egress_system_addon", path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class SystemAddonRedactionTest(unittest.TestCase):
    def test_load_active_vault_reads_unix_socket(self) -> None:
        system = _load_system_module()
        calls: list[tuple[str, Any, Any]] = []

        class FakeResponse:
            status = 200

            def read(self) -> bytes:
                return json.dumps(
                    {
                        "revision": 7,
                        "bindings": [
                            {
                                "name": "gitlab-api",
                                "headers": [
                                    {"name": "Private-Token", "value": "secret-token"}
                                ],
                            }
                        ],
                        "redactions": ["secret-token"],
                    }
                ).encode("utf-8")

        class FakeConnection:
            def __init__(self, socket_path: str, timeout: float) -> None:
                calls.append(("init", socket_path, timeout))

            def request(self, method: str, path: str) -> None:
                calls.append(("request", method, path))

            def getresponse(self) -> FakeResponse:
                calls.append(("getresponse", None, None))
                return FakeResponse()

            def close(self) -> None:
                calls.append(("close", None, None))

        old_socket = os.environ.get(system.CREDENTIAL_PROXY_SOCKET_ENV)
        old_connection = system.UnixSocketHTTPConnection
        os.environ[system.CREDENTIAL_PROXY_SOCKET_ENV] = "/tmp/active.sock"
        system.UnixSocketHTTPConnection = FakeConnection
        try:
            vault = system._load_active_vault()
        finally:
            system.UnixSocketHTTPConnection = old_connection
            if old_socket is None:
                os.environ.pop(system.CREDENTIAL_PROXY_SOCKET_ENV, None)
            else:
                os.environ[system.CREDENTIAL_PROXY_SOCKET_ENV] = old_socket

        self.assertIsNotNone(vault)
        assert vault is not None
        self.assertEqual(7, vault.revision)
        self.assertEqual(["secret-token"], vault.redactions)
        self.assertEqual(("init", "/tmp/active.sock", 0.25), calls[0])
        self.assertEqual(("request", "GET", system.ACTIVE_VAULT_PATH), calls[1])
        self.assertEqual(("close", None, None), calls[-1])

    def test_request_injection_log_does_not_include_secret_value(self) -> None:
        system = _load_system_module()
        flow = _Flow()
        system._load_active_vault = lambda: system.ActiveVault(
            1,
            [
                {
                    "name": "gitlab-api",
                    "match": {
                        "hosts": ["code.example.com"],
                        "methods": ["GET"],
                        "paths": ["/api/v8/*"],
                    },
                    "headers": [{"name": "Private-Token", "value": "secret-token"}],
                }
            ],
            ["secret-token"],
        )

        system.request(flow)

        self.assertEqual("secret-token", flow.request.headers.get("Private-Token"))
        self.assertNotIn("secret-token", "\n".join(system.ctx.log.messages))

    def test_response_redacts_headers_and_body(self) -> None:
        system = _load_system_module()
        flow = _Flow()
        flow.metadata[system.FLOW_REDACTIONS_KEY] = ["secret-token"]
        flow.response.headers["content-encoding"] = "gzip"
        flow.response.headers["content-length"] = "42"

        system.responseheaders(flow)
        system.response(flow)

        self.assertEqual("[REDACTED]", flow.response.headers.get("x-token-echo"))
        self.assertEqual(b"upstream body includes [REDACTED]", flow.response.body)
        self.assertTrue(flow.response.set_content_called)
        self.assertFalse(flow.response.set_text_called)

    def test_responseheaders_streams_unknown_length_body_through_redactor(self) -> None:
        system = _load_system_module()
        flow = _Flow()
        flow.metadata[system.FLOW_REDACTIONS_KEY] = ["secret-token"]

        system.responseheaders(flow)

        self.assertTrue(callable(flow.response.stream))
        output = b"".join(
            [flow.response.stream(b"secret-token"), flow.response.stream(b"")]
        )
        self.assertEqual(b"[REDACTED]", output)

    def test_responseheaders_removes_content_length_before_stream_redaction(
        self,
    ) -> None:
        system = _load_system_module()
        flow = _Flow()
        flow.metadata[system.FLOW_REDACTIONS_KEY] = ["secret-token"]
        flow.response.headers["content-length"] = "42"

        system.responseheaders(flow)

        self.assertNotIn("content-length", flow.response.headers)
        self.assertTrue(callable(flow.response.stream))

    def test_compressed_streaming_response_is_terminated(self) -> None:
        system = _load_system_module()
        flow = _Flow()
        flow.metadata[system.FLOW_REDACTIONS_KEY] = ["secret-token"]
        flow.response.headers["content-encoding"] = "gzip"
        flow.response.headers["transfer-encoding"] = "chunked"

        system.responseheaders(flow)

        self.assertTrue(flow.killed)

    def test_unknown_length_compressed_response_is_terminated(self) -> None:
        system = _load_system_module()
        flow = _Flow()
        flow.metadata[system.FLOW_REDACTIONS_KEY] = ["secret-token"]
        flow.response.headers["content-encoding"] = "gzip"

        system.responseheaders(flow)

        self.assertTrue(flow.killed)

    def test_head_response_is_forwarded_without_body_redaction(self) -> None:
        system = _load_system_module()
        flow = _Flow()
        flow.request.method = "HEAD"
        flow.metadata[system.FLOW_REDACTIONS_KEY] = ["secret-token"]
        flow.response.headers["content-length"] = "42"

        system.responseheaders(flow)

        self.assertFalse(flow.killed)
        self.assertFalse(flow.response.stream)
        self.assertEqual("42", flow.response.headers.get("content-length"))

    def test_response_ignores_missing_body(self) -> None:
        system = _load_system_module()
        flow = _Flow()
        flow.metadata[system.FLOW_REDACTIONS_KEY] = ["secret-token"]
        flow.response.get_content = lambda strict=True: None

        system.response(flow)

        self.assertFalse(flow.response.set_content_called)

    def test_redaction_prefers_longer_overlapping_secret(self) -> None:
        system = _load_system_module()

        redacted = system._redact_bytes(b"token-long", ["token", "token-long"])

        self.assertEqual(b"[REDACTED]", redacted)
        self.assertEqual(
            "[REDACTED]",
            system._redact_text("token-long", ["token", "token-long"]),
        )

    def test_stream_redacts_secret_split_across_chunks(self) -> None:
        system = _load_system_module()
        transform = system._redacting_stream(["secret-token"])

        output = b"".join(
            [
                transform(b"prefix secret-"),
                transform(b"token suffix"),
                transform(b""),
            ]
        )

        self.assertEqual(b"prefix [REDACTED] suffix", output)
        self.assertNotIn(b"secret-token", output)

    def test_responseheaders_uses_injected_flow_redactions(self) -> None:
        system = _load_system_module()
        flow = _Flow()
        system._load_active_vault = lambda: system.ActiveVault(
            1,
            [
                {
                    "name": "gitlab-api",
                    "match": {"hosts": ["code.example.com"]},
                    "headers": [{"name": "Private-Token", "value": "old-secret"}],
                }
            ],
            ["old-secret"],
        )

        system.request(flow)
        system._load_active_vault = lambda: system.ActiveVault(2, [], ["new-secret"])
        flow.response.headers["x-token-echo"] = "old-secret"
        system.responseheaders(flow)

        self.assertEqual("[REDACTED]", flow.response.headers.get("x-token-echo"))


if __name__ == "__main__":
    unittest.main()
