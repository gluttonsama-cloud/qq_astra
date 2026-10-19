"""Offline tests only: all DNS, sockets, TLS, and HTTP delivery are mocked."""

import base64
import socket
import ssl
import time
import unittest
from unittest.mock import MagicMock, patch

from standardwebhooks import Webhook, WebhookVerificationError

from bridge_service import webhooks


SECRET = "whsec_" + base64.b64encode(b"fixture-signing-key-never-a-real-key").decode()
OLD_SECRET = "whsec_" + base64.b64encode(b"old-fixture-key-not-real-credentials").decode()
URL = "https://callbacks.example.test/events?key=fixture"
BODY = '{ "eventId": "evt_fixture", "text": "你好" }\n'.encode()


def address(ip="8.8.8.8"):
    if ":" in ip:
        return (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443, 0, 0))
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443))


class SigningTests(unittest.TestCase):
    def test_secret_boundaries_and_unpadded_base64(self):
        for size in (24, 32, 64):
            for padded in (True, False):
                encoded = base64.b64encode(b"a" * size).decode()
                if not padded:
                    encoded = encoded.rstrip("=")
                self.assertEqual(webhooks.validate_secret("whsec_" + encoded), b"a" * size)

    def test_invalid_secrets(self):
        invalid = [None, "", "wrong_" + SECRET[6:], "whsec_%%!", SECRET + "=", SECRET + "\n"]
        invalid += ["whsec_" + base64.b64encode(b"a" * n).decode() for n in (0, 23, 65)]
        for secret in invalid:
            with self.subTest(secret=secret), self.assertRaises(ValueError):
                webhooks.validate_secret(secret)

    def test_exact_body_verifies_with_official_library(self):
        now = time.time()
        headers = webhooks.signed_headers(SECRET, "evt_fixture", BODY, now, "sub_fixture")
        self.assertEqual(headers["webhook-timestamp"], str(int(now)))
        self.assertEqual(headers["X-MCP-Subscription-Id"], "sub_fixture")
        self.assertEqual(headers["Content-Type"], "application/json")
        verified = Webhook(SECRET).verify(BODY, headers)
        self.assertEqual(verified["text"], "你好")
        with self.assertRaises(WebhookVerificationError):
            Webhook(SECRET).verify(BODY.rstrip(), headers)

    def test_retry_keeps_id_and_refreshes_timestamp_and_signature(self):
        first = webhooks.signed_headers(SECRET, "evt_fixture", BODY, 1000.9, "sub_fixture")
        retry = webhooks.signed_headers(SECRET, "evt_fixture", BODY, 1001.1, "sub_fixture")
        self.assertEqual(first["webhook-id"], retry["webhook-id"])
        self.assertEqual(retry["webhook-timestamp"], "1001")
        self.assertNotEqual(first["webhook-signature"], retry["webhook-signature"])

    def test_rotation_is_verifiable_by_both_keys(self):
        headers = webhooks.signed_headers(SECRET, "evt_fixture", BODY, time.time(), "sub_fixture", OLD_SECRET)
        self.assertEqual(len(headers["webhook-signature"].split(" ")), 2)
        self.assertEqual(Webhook(SECRET).verify(BODY, headers), Webhook(OLD_SECRET).verify(BODY, headers))

    def test_signing_rejects_wrong_body_type_invalid_utf8_and_oversize(self):
        for body, error in [("{}", TypeError), (b"\xff", UnicodeDecodeError), (b"x" * (256 * 1024 + 1), ValueError)]:
            with self.subTest(body_type=type(body)), self.assertRaises(error):
                webhooks.signed_headers(SECRET, "evt_fixture", body, 1000, "sub_fixture")

    def test_signing_rejects_bad_timestamp_or_header_injection(self):
        for now in (-1, float("inf"), float("nan")):
            with self.subTest(now=now), self.assertRaises(ValueError):
                webhooks.signed_headers(SECRET, "evt_fixture", BODY, now, "sub_fixture")
        for event_id, subscription_id in [("bad\r\nHost: other", "sub"), ("evt", "bad\nvalue"), ("", "sub")]:
            with self.subTest(event_id=event_id), self.assertRaises(ValueError):
                webhooks.signed_headers(SECRET, event_id, BODY, 1000, subscription_id)


class CallbackURLTests(unittest.TestCase):
    def test_valid_https_url_and_explicit_443(self):
        self.assertEqual(webhooks.validate_callback_url(URL).hostname, "callbacks.example.test")
        self.assertEqual(webhooks.validate_callback_url("https://example.test:443/").port, 443)
        self.assertEqual(webhooks.validate_callback_url("https://[2606:4700:4700::1111]/").hostname, "2606:4700:4700::1111")

    def test_rejects_ambiguous_or_unsafe_url_syntax(self):
        urls = ["http://example.test", "//example.test", "https:///path", "https://user:pass@example.test",
                "https://@example.test", "https://example.test/#", "https://example.test/#fragment",
                "https://example.test:8443/", "https://example.test:0", "https://example.test:/",
                "https://example.test:invalid/", "https://[broken", " https://example.test/",
                "https://example.test/\r\nHeader: injected", "https://example.test\\@other.test/",
                "https://[fe80::1%25eth0]/", "https://%31%32%37.0.0.1/", "https://a..example.test/",
                "https://例子.test/"]
        for url in urls:
            with self.subTest(url=url), self.assertRaises(ValueError):
                webhooks.validate_callback_url(url)


class ConnectionTests(unittest.TestCase):
    def setUp(self):
        self.context = MagicMock(spec=ssl.SSLContext)
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.check_hostname = True

    def connection(self):
        return webhooks._PublicHTTPSConnection("callbacks.example.test", 443, timeout=3, context=self.context)

    @patch.object(webhooks.socket, "socket")
    @patch.object(webhooks.socket, "getaddrinfo")
    def test_private_local_shared_reserved_multicast_and_tunnel_ips_rejected(self, resolve, socket_factory):
        unsafe = ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254",
                  "100.64.0.1", "0.0.0.0", "192.0.2.1", "224.0.0.1", "240.0.0.1",
                  "::1", "fe80::1", "fd00::1", "2001:db8::1", "ff02::1", "::ffff:127.0.0.1",
                  "64:ff9b::7f00:1", "2002:7f00:1::"]
        for ip in unsafe:
            resolve.return_value = [address(ip)]
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                self.connection().connect()
        socket_factory.assert_not_called()

    @patch.object(webhooks.socket, "socket")
    @patch.object(webhooks.socket, "getaddrinfo")
    def test_all_dns_addresses_checked_before_connecting(self, resolve, socket_factory):
        resolve.return_value = [address(), address("127.0.0.1")]
        with self.assertRaises(ValueError):
            self.connection().connect()
        socket_factory.assert_not_called()

    @patch.object(webhooks.socket, "socket")
    @patch.object(webhooks.socket, "getaddrinfo", return_value=[])
    def test_empty_dns_answer_fails_closed(self, resolve, socket_factory):
        with self.assertRaises(OSError):
            self.connection().connect()
        socket_factory.assert_not_called()

    @patch.object(webhooks.socket, "socket")
    @patch.object(webhooks.socket, "getaddrinfo", return_value=[address("2606:4700:4700::1111")])
    def test_public_ipv6_uses_validated_sockaddr(self, resolve, socket_factory):
        self.connection().connect()
        socket_factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        socket_factory.return_value.connect.assert_called_once_with(("2606:4700:4700::1111", 443, 0, 0))

    @patch.object(webhooks.socket, "socket")
    @patch.object(webhooks.socket, "getaddrinfo")
    def test_pins_numeric_address_and_preserves_tls_hostname(self, resolve, socket_factory):
        resolve.return_value = [address()]
        raw_socket = socket_factory.return_value
        connection = self.connection()
        connection.connect()
        resolve.assert_called_once_with("callbacks.example.test", 443, type=socket.SOCK_STREAM)
        raw_socket.connect.assert_called_once_with(("8.8.8.8", 443))
        raw_socket.settimeout.assert_called_once_with(3)
        self.context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="callbacks.example.test")
        self.assertIs(connection.sock, self.context.wrap_socket.return_value)

    @patch.object(webhooks.socket, "socket")
    @patch.object(webhooks.socket, "getaddrinfo")
    def test_each_connection_rechecks_dns_rebinding(self, resolve, socket_factory):
        resolve.side_effect = [[address()], [address("127.0.0.1")]]
        self.connection().connect()
        with self.assertRaises(ValueError):
            self.connection().connect()
        self.assertEqual(resolve.call_count, 2)
        self.assertEqual(socket_factory.call_count, 1)

    @patch.object(webhooks.socket, "socket")
    @patch.object(webhooks.socket, "getaddrinfo", return_value=[address()])
    def test_tls_verification_failure_closes_socket(self, resolve, socket_factory):
        self.context.wrap_socket.side_effect = ssl.SSLCertVerificationError("fixture untrusted")
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connection().connect()
        socket_factory.return_value.close.assert_called_once()

    @patch.object(webhooks.socket, "socket")
    @patch.object(webhooks.socket, "getaddrinfo", return_value=[address()])
    def test_original_host_header_is_sent_with_pinned_connection(self, resolve, socket_factory):
        connection = self.connection()
        connection.request("POST", "/events", body=BODY, headers={"Content-Type": "application/json"})
        wire = b"".join(call.args[0] for call in connection.sock.sendall.call_args_list)
        self.assertIn(b"Host: callbacks.example.test\r\n", wire)
        self.assertNotIn(b"Host: 8.8.8.8", wire)
        self.assertTrue(wire.endswith(BODY))


class TransportTests(unittest.TestCase):
    @patch.object(webhooks.socket, "getaddrinfo", side_effect=AssertionError("unexpected network"))
    def test_disabled_transport_cannot_deliver(self, resolve):
        with self.assertRaisesRegex(RuntimeError, "disabled"):
            webhooks.DisabledWebhookTransport().post(URL, BODY, {})
        resolve.assert_not_called()

    @patch.object(webhooks, "_PublicHTTPSConnection")
    def test_redirect_is_returned_without_following(self, connection_class):
        connection = connection_class.return_value
        connection.getresponse.return_value.status = 302
        connection.getresponse.return_value.read.return_value = b"redirect not followed"
        connection.getresponse.return_value.getheader.return_value = "http://127.0.0.1/"
        result = webhooks.PublicWebhookTransport(timeout=2).post(URL, BODY, {"webhook-id": "evt_fixture"})
        self.assertEqual(result, (302, b"redirect not followed"))
        connection_class.assert_called_once()
        self.assertEqual(connection_class.call_args.kwargs["timeout"], 2)
        context = connection_class.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        connection.request.assert_called_once_with("POST", "/events?key=fixture", body=BODY, headers={"webhook-id": "evt_fixture"})
        connection.getresponse.return_value.read.assert_called_once_with(64 * 1024 + 1)
        connection.close.assert_called_once()

    @patch.object(webhooks, "_PublicHTTPSConnection")
    def test_response_size_cap_and_cleanup(self, connection_class):
        connection = connection_class.return_value
        connection.getresponse.return_value.read.return_value = b"x" * (64 * 1024 + 1)
        with self.assertRaisesRegex(ValueError, "64 KiB"):
            webhooks.PublicWebhookTransport().post(URL, BODY, {})
        connection.close.assert_called_once()

    @patch.object(webhooks, "_PublicHTTPSConnection")
    def test_exact_response_limit_accepted(self, connection_class):
        connection = connection_class.return_value
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.read.return_value = b"x" * (64 * 1024)
        self.assertEqual(len(webhooks.PublicWebhookTransport().post(URL, BODY, {})[1]), 64 * 1024)

    @patch.object(webhooks, "_PublicHTTPSConnection")
    def test_timeout_propagates_and_closes_connection(self, connection_class):
        connection = connection_class.return_value
        connection.request.side_effect = TimeoutError("fixture timeout")
        with self.assertRaises(TimeoutError):
            webhooks.PublicWebhookTransport().post(URL, BODY, {})
        connection.close.assert_called_once()

    @patch.object(webhooks, "_PublicHTTPSConnection")
    def test_cannot_override_host_or_body_framing(self, connection_class):
        for name in ("Host", "CONTENT-LENGTH", "Transfer-Encoding", "Connection"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                webhooks.PublicWebhookTransport().post(URL, BODY, {name: "fixture"})
        connection_class.assert_not_called()

    @patch.object(webhooks.socket, "getaddrinfo", side_effect=AssertionError("unexpected network"))
    def test_bad_request_rejected_before_dns_or_socket(self, resolve):
        for url, body, error in [("http://example.test", BODY, ValueError),
                                 (URL, "{}", TypeError),
                                 (URL, b"x" * (256 * 1024 + 1), ValueError)]:
            with self.subTest(url=url, body_type=type(body)), self.assertRaises(error):
                webhooks.PublicWebhookTransport().post(url, body, {})
        resolve.assert_not_called()

    def test_timeout_must_be_finite_and_positive(self):
        for timeout in (0, -1, float("inf"), float("nan")):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                webhooks.PublicWebhookTransport(timeout)


if __name__ == "__main__":
    unittest.main()
