"""Loopback proxy regression tests; mocked sockets, no credentials or ACL changes."""

import io
import json
import os
import socket
import ssl
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from . import runtime, webhooks


PROXY = "http://127.0.0.1:8080"
HOST = "callbacks.example.test"


def address(ip="8.8.8.8"):
    if ":" in ip:
        return socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443, 0, 0)
    return socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443)


class ProxyConfigurationTests(unittest.TestCase):
    def test_only_explicit_credential_free_loopback_urls(self):
        for url, expected in ((None, None), (PROXY, ("127.0.0.1", 8080)),
                              ("http://[::1]:1234/", ("::1", 1234))):
            with self.subTest(url=url):
                self.assertEqual(webhooks.validate_proxy_url(url), expected)
        invalid = [True, 123, "", "http://localhost:8080", "http://127.0.0.2:8080",
                   "http://192.168.1.1:8080", "http://8.8.8.8:8080", "http://127.0.0.1",
                   "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://[::1",
                   "https://127.0.0.1:8080", "socks5://127.0.0.1:8080", "http://2130706433:8080",
                   "http://user:password@127.0.0.1:8080", "http://@127.0.0.1:8080",
                   PROXY + "/path", PROXY + "?", PROXY + "#", PROXY + "\n",
                   PROXY + "\\path", " " + PROXY, "http://[::1%lo]:8080", "http://%31%32%37.0.0.1:8080"]
        with patch.object(webhooks.socket, "socket") as factory:
            for url in invalid:
                with self.subTest(url=url), self.assertRaises(ValueError):
                    webhooks.PublicWebhookTransport(proxy_url=url)
            factory.assert_not_called()

    def test_environment_proxy_is_never_adopted(self):
        with patch.dict(os.environ, {"HTTP_PROXY": PROXY, "HTTPS_PROXY": PROXY,
                                     "ALL_PROXY": PROXY, "NO_PROXY": "*"}), \
             patch.object(webhooks, "_PublicHTTPSConnection") as connection:
            connection.return_value.getresponse.return_value.read.return_value = b"{}"
            webhooks.PublicWebhookTransport().post("https://" + HOST + "/events", b"{}", {})
            self.assertIsNone(connection.call_args.kwargs["proxy"])
            webhooks.PublicWebhookTransport(proxy_url=PROXY).post("https://" + HOST + "/events", b"{}", {})
            self.assertEqual(connection.call_args.kwargs["proxy"], ("127.0.0.1", 8080))
            context = connection.call_args.kwargs["context"]
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)

    def config(self):
        return {"public_resource_url": "https://bridge.example.test/mcp", "oauth_issuer": "https://issuer.example.test/",
                "owner_subject": "synthetic", "jwks_file": "public-jwks.json", "onebot_url": "http://127.0.0.1:3000",
                "onebot_token_file": "onebot.token", "state_key_file": "state.key", "account_id": 100001, "peer_id": 100002}

    def test_config_load_accepts_optional_proxy_and_rejects_bad_value(self):
        for value in (None, PROXY, "http://remote.example.test:8080"):
            config = {**self.config(), "webhook_proxy_url": value}
            with patch.object(runtime, "read_secret_file", return_value=json.dumps(config)):
                if value == "http://remote.example.test:8080":
                    with self.assertRaises(ValueError):
                        runtime.load_config(Path("synthetic/config.json"))
                else:
                    self.assertEqual(runtime.load_config(Path("synthetic/config.json"))["webhook_proxy_url"], value)

    def test_configuration_check_rejects_proxy_before_loading_secrets(self):
        with patch.object(runtime, "Authenticator") as auth, patch.object(runtime, "read_secret_file") as read:
            with self.assertRaises(ValueError):
                runtime.validate_configuration({**self.config(), "webhook_proxy_url": "http://remote.example.test:8080"})
            auth.assert_not_called()
            read.assert_not_called()

    def test_application_passes_operator_proxy_to_webhook_transport(self):
        for proxy in (None, PROXY):
            with self.subTest(proxy=proxy), \
                 patch.object(runtime, "validate_configuration", return_value=(MagicMock(), "synthetic", MagicMock(), MagicMock())), \
                 patch.object(runtime, "StateDirectory"), patch.object(runtime, "Bridge"), \
                 patch.object(runtime, "Application"), patch.object(runtime, "PublicWebhookTransport") as transport:
                runtime.create_application({**self.config(), "webhook_proxy_url": proxy})
                transport.assert_called_once_with(timeout=10, proxy_url=proxy)


class ProxyConnectionTests(unittest.TestCase):
    def setUp(self):
        self.context = MagicMock(spec=ssl.SSLContext)
        self.context.wrap_socket.return_value.send.side_effect = len
        self.raw = MagicMock()
        self.raw.send.side_effect = len
        self.respond(b"HTTP/1.1 200 Connection established\r\nContent-Length: 0\r\n\r\n")

    def respond(self, data):
        self.response = io.BytesIO(data)
        self.raw.recv.side_effect = self.response.read

    def connection(self, proxy=PROXY, timeout=3):
        return webhooks._PublicHTTPSConnection(HOST, 443, timeout=timeout, context=self.context,
                                              proxy=webhooks.validate_proxy_url(proxy))

    def test_numeric_connect_ipv4_ipv6_and_end_to_end_host_binding(self):
        for target, proxy, local, authority in (
            ("8.8.8.8", PROXY, ("127.0.0.1", 8080), "8.8.8.8:443"),
            ("2606:4700:4700::1111", PROXY, ("127.0.0.1", 8080), "[2606:4700:4700::1111]:443"),
            ("8.8.8.8", "http://[::1]:8080", ("::1", 8080, 0, 0), "8.8.8.8:443"),
        ):
            with self.subTest(target=target, proxy=proxy):
                self.setUp()
                with patch.object(webhooks.socket, "getaddrinfo", return_value=[address(target)]) as dns, \
                     patch.object(webhooks.socket, "socket", return_value=self.raw):
                    self.connection(proxy).request("POST", "/events?private=fixture", body=b"synthetic-private-body",
                                                   headers={"webhook-signature": "synthetic-signature"})
                dns.assert_called_once_with(HOST, 443, type=socket.SOCK_STREAM)
                self.raw.connect.assert_called_once_with(local)
                plain = b"".join(call.args[0] for call in self.raw.send.call_args_list)
                self.assertEqual(plain, f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
                self.context.wrap_socket.assert_called_once_with(self.raw, server_hostname=HOST)
                encrypted = b"".join(call.args[0] for call in self.context.wrap_socket.return_value.send.call_args_list)
                self.assertIn(b"Host: callbacks.example.test\r\n", encrypted)
                self.assertIn(b"webhook-signature: synthetic-signature", encrypted)
                self.assertTrue(encrypted.endswith(b"synthetic-private-body"))

    def test_all_public_dns_checks_happen_before_contacting_proxy(self):
        for records in ([], [address("127.0.0.1")], [address(), address("10.0.0.1")],
                        [address("198.18.0.1")], [address("169.254.169.254")], [address("::ffff:127.0.0.1")]):
            with self.subTest(records=records), patch.object(webhooks, "_resolve", return_value=records), \
                 patch.object(webhooks.socket, "socket") as factory:
                with self.assertRaises((ValueError, OSError)):
                    self.connection().connect()
                factory.assert_not_called()
        with patch.object(webhooks, "_resolve", side_effect=socket.gaierror("synthetic DNS failure")), \
             patch.object(webhooks.socket, "socket") as factory:
            with self.assertRaises(socket.gaierror):
                self.connection().connect()
            factory.assert_not_called()

    def test_rebinding_is_rechecked_on_every_proxy_connection(self):
        with patch.object(webhooks, "_resolve", side_effect=[[address()], [address("10.0.0.1")]]), \
             patch.object(webhooks.socket, "socket", return_value=self.raw) as factory:
            self.connection().connect()
            with self.assertRaises(ValueError):
                self.connection().connect()
            factory.assert_called_once()

    def test_rejection_and_malformed_responses_do_not_send_tls_or_fall_back(self):
        bad = [b"HTTP/1.1 407 Authentication required\r\nProxy-Authenticate: fixture\r\n\r\n",
               b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/\r\n\r\n",
               b"HTTP/1.1 500 Error\r\n\r\n", b"HTTP/2.0 200 OK\r\n\r\n",
               b"HTTP/1.1 200 OK\r\n folded: invalid\r\n\r\n",
               b"HTTP/1.1 200 OK\r\nBad header\r\n\r\n",
               b"HTTP/1.1 200 OK\r\nX: \x00\r\n\r\n",
               b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx",
               b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
               b"HTTP/1.1 200 OK\r\n", b"HTTP/1.1 200 OK\n\n", b""]
        for response in bad:
            with self.subTest(response=response):
                self.setUp()
                self.respond(response)
                with patch.object(webhooks, "_resolve", return_value=[address()]), \
                     patch.object(webhooks.socket, "socket", return_value=self.raw):
                    with self.assertRaises((ValueError, OSError)):
                        self.connection().request("POST", "/private", body=b"never-send")
                self.context.wrap_socket.assert_not_called()
                self.raw.connect.assert_called_once_with(("127.0.0.1", 8080))
                self.raw.close.assert_called_once()
                self.assertNotIn(b"never-send", b"".join(c.args[0] for c in self.raw.send.call_args_list))

    def test_connect_header_bound_and_no_read_ahead(self):
        for response, fails in ((b"HTTP/1.0 200 OK\r\n\r\nTLS-sentinel", False),
                                (b"HTTP/1.1 200 OK\r\nX: " + b"x" * webhooks.MAX_CONNECT_HEADER_BYTES, True)):
            with self.subTest(fails=fails):
                self.setUp()
                self.respond(response)
                with patch.object(webhooks, "_resolve", return_value=[address()]), \
                     patch.object(webhooks.socket, "socket", return_value=self.raw):
                    if fails:
                        with self.assertRaises(ValueError):
                            self.connection().connect()
                        self.assertEqual(self.raw.recv.call_count, webhooks.MAX_CONNECT_HEADER_BYTES)
                        self.context.wrap_socket.assert_not_called()
                        self.raw.close.assert_called_once()
                    else:
                        self.connection().connect()
                        self.assertEqual(self.response.read(), b"TLS-sentinel")

    def test_proxy_socket_and_certificate_failure_close_without_direct_fallback(self):
        for stage in ("connect", "tls"):
            with self.subTest(stage=stage):
                self.setUp()
                if stage == "connect":
                    self.raw.connect.side_effect = ConnectionRefusedError("synthetic refusal")
                else:
                    self.context.wrap_socket.side_effect = ssl.SSLCertVerificationError("synthetic untrusted cert")
                with patch.object(webhooks, "_resolve", return_value=[address()]), \
                     patch.object(webhooks.socket, "socket", return_value=self.raw):
                    with self.assertRaises(OSError):
                        self.connection().request("POST", "/private", body=b"never-send")
                self.raw.connect.assert_called_once_with(("127.0.0.1", 8080))
                self.raw.close.assert_called_once()
                self.context.wrap_socket.return_value.send.assert_not_called()

    def test_slow_connect_response_obeys_shared_deadline(self):
        clock = [100.0]
        def read(size):
            clock[0] += 0.4
            return self.response.read(size)
        self.raw.recv.side_effect = read
        with patch.object(webhooks.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(webhooks, "_resolve", return_value=[address(), address("1.1.1.1")]), \
             patch.object(webhooks.socket, "socket", return_value=self.raw) as factory:
            with self.assertRaises(TimeoutError):
                self.connection(timeout=1).connect()
        factory.assert_called_once()
        self.raw.close.assert_called_once()
        self.context.wrap_socket.assert_not_called()

    def test_tls_cannot_reset_deadline_used_by_dns_and_proxy(self):
        clock = [100.0]
        def resolve(*args):
            clock[0] += 0.4
            return [address()]
        def connect(*args):
            clock[0] += 0.4
        def wrap(*args, **kwargs):
            clock[0] += 0.3
            return self.context.wrap_socket.return_value
        self.raw.connect.side_effect = connect
        self.context.wrap_socket.side_effect = wrap
        with patch.object(webhooks.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(webhooks, "_resolve", side_effect=resolve), \
             patch.object(webhooks.socket, "socket", return_value=self.raw):
            with self.assertRaises(TimeoutError):
                self.connection(timeout=1).request("POST", "/private", body=b"never-send")
        self.context.wrap_socket.return_value.close.assert_called_once()
        self.context.wrap_socket.return_value.send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
