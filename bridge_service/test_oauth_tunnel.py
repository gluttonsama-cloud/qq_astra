"""Portable OAuth/Tunnel regressions: ephemeral keys and mocked network only."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import io
import json
import os
from pathlib import Path
import socket
import ssl
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from . import auth, runtime, webhooks


ISSUER = "https://tenant.example/"
RESOURCE = "https://tunnel.example/v1/mcp/tunnel_synthetic"


class _KeyFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.next_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.ec_private = ec.generate_private_key(ec.SECP256R1())

    @staticmethod
    def jwk(key, kid, algorithm="RS256"):
        factory = jwt.algorithms.RSAAlgorithm if algorithm == "RS256" else jwt.algorithms.ECAlgorithm
        return {**json.loads(factory.to_jwk(key.public_key())), "kid": kid, "alg": algorithm, "use": "sig"}

    def setUp(self):
        self.document = {"keys": [self.jwk(self.private, "current"), self.jwk(self.ec_private, "ec", "ES256")]}
        # ACL/path validation is separately exercised by platform tests. No
        # production trust file or private test key is written by this fixture.
        reader = patch.object(auth, "read_public_key_file", side_effect=lambda *a, **k: json.dumps(self.document).encode())
        self.reader = reader.start()
        self.addCleanup(reader.stop)
        self.settings = dict(issuer=ISSUER, public_resource_url=RESOURCE, owner_subject="synthetic-owner")
        self.validator = auth.Authenticator(**self.settings, jwks_path="synthetic-public.json")
        now = int(time.time())
        self.claims = {"iss": ISSUER, "aud": RESOURCE, "sub": "synthetic-owner",
                       "iat": now - 1, "exp": now + 300, "scope": "qq:read qq:events qq:reply"}

    def token(self, changes=None, headers=None, key=None, algorithm="RS256"):
        return jwt.encode({**self.claims, **(changes or {})}, key or self.private, algorithm=algorithm,
                          headers={"typ": "at+jwt", "kid": "current", **(headers or {})})

    def rejected(self, token, status=401, scope="qq:read"):
        with self.assertRaises(auth.AuthError) as caught:
            self.validator.authenticate("Bearer " + token, scope)
        self.assertEqual(caught.exception.status_code, status)
        self.assertNotIn(token, str(caught.exception))


class TokenContractTests(_KeyFixture):
    def test_string_and_array_audience_exact_membership(self):
        for value in (RESOURCE, [RESOURCE], [ISSUER + "userinfo", RESOURCE], [RESOURCE, "another-api"]):
            with self.subTest(aud=value):
                self.assertEqual(self.validator.authenticate("Bearer " + self.token({"aud": value}), "qq:read"), "synthetic-owner")
        for value in (None, "", [], [""], [RESOURCE, ""], [RESOURCE, None], [RESOURCE, 1],
                      [RESOURCE, False], [[RESOURCE]], {"aud": RESOURCE}, 123, False,
                      [RESOURCE.upper()], [RESOURCE + "/"], ["another-api"], RESOURCE + "/other"):
            with self.subTest(aud=value):
                self.rejected(self.token({"aud": value}))

    def test_all_existing_identity_signature_time_and_scope_checks_remain(self):
        now = int(time.time())
        for values in ({"iss": ISSUER.rstrip("/")}, {"iss": "https://attacker.example/"},
                       {"sub": "stranger"}, {"sub": 1}, {"exp": now - 1}, {"iat": now + 60},
                       {"nbf": now + 60}, {"iat": False}, {"exp": "invalid"}, {"token_use": "id"},
                       {"scope": ["qq:read"]}, {"scope": "qq:read\tqq:reply"}):
            with self.subTest(values=values):
                self.rejected(self.token({"aud": [RESOURCE, ISSUER + "userinfo"], **values}))
        for field in ("iss", "aud", "sub", "exp", "iat", "scope"):
            claims = {k: v for k, v in self.claims.items() if k != field}
            self.rejected(jwt.encode(claims, self.private, algorithm="RS256", headers={"typ": "at+jwt", "kid": "current"}))
        for headers in ({"typ": "JWT"}, {"typ": "id+jwt"}, {"kid": "unknown"}, {"crit": ["custom"]},
                        {"jku": "http://127.0.0.1/jwks"}, {"x5u": "https://attacker.example/"}, {"jwk": self.document["keys"][0]}):
            self.rejected(self.token(headers=headers))
        self.rejected(self.token(key=self.next_private))
        self.rejected(self.token(key="synthetic-only-secret-that-is-not-a-real-key", algorithm="HS256"))
        self.rejected(self.token({"scope": "qq:read"}), status=403, scope="qq:reply")
        self.assertEqual(self.validator.authenticate("Bearer " + self.token(key=self.ec_private, algorithm="ES256", headers={"kid": "ec"})), "synthetic-owner")

    def test_local_file_rotation_still_reloads_and_fails_closed(self):
        previous = self.token()
        self.document = {"keys": [self.jwk(self.next_private, "next")]}
        self.rejected(previous)
        self.assertEqual(self.validator.authenticate("Bearer " + self.token(key=self.next_private, headers={"kid": "next"})), "synthetic-owner")
        self.document = {"keys": []}
        self.rejected(previous, status=503)


class IssuerCacheTests(_KeyFixture):
    def setUp(self):
        super().setUp()
        self.validator = auth.Authenticator(**self.settings, jwks_from_issuer=True)
        self.cache = self.validator.issuer_keys
        self.now = 1000
        self.cache.clock = lambda: self.now
        mock = patch.object(self.cache, "_fetch", side_effect=lambda: auth._parse_keys(json.dumps(self.document)))
        self.fetch = mock.start()
        self.addCleanup(mock.stop)

    def valid(self, **kwargs):
        self.assertEqual(self.validator.authenticate("Bearer " + self.token(**kwargs), "qq:read"), "synthetic-owner")

    def test_lazy_cache_ttl_rotation_and_removed_key(self):
        self.fetch.assert_not_called()
        self.valid()
        self.valid()
        self.assertEqual(self.fetch.call_count, 1)
        self.document["keys"].append(self.jwk(self.next_private, "next"))
        self.rejected(self.token(key=self.next_private, headers={"kid": "next"}))
        self.assertEqual(self.fetch.call_count, 1)
        self.now += 60
        self.valid(key=self.next_private, headers={"kid": "next"})
        self.valid()
        self.document = {"keys": [self.jwk(self.next_private, "next")]}
        self.now += 300
        self.valid(key=self.next_private, headers={"kid": "next"})
        self.rejected(self.token())
        self.assertEqual(self.fetch.call_count, 3)

    def test_unknown_kid_storm_and_invalid_headers_do_not_amplify_fetches(self):
        for headers in ({"typ": "JWT"}, {"kid": ""}, {"kid": "x" * 257},
                        {"jku": "https://attacker.example/"}, {"x5u": "http://127.0.0.1/"}):
            self.rejected(self.token(headers=headers))
        self.fetch.assert_not_called()
        for i in range(80):
            self.rejected(self.token(headers={"kid": f"unknown-{i}"}))
        self.assertEqual(self.fetch.call_count, 1)
        self.now += 60
        self.rejected(self.token(headers={"kid": "different-unknown"}))
        self.assertEqual(self.fetch.call_count, 2)
        self.assertEqual(len(self.cache.keys), 2)

    def test_failed_refresh_drops_even_fresh_keys_and_recovers_after_cooldown(self):
        self.valid()
        self.now += 60
        self.fetch.side_effect = TimeoutError("must not leak remote diagnostic")
        self.rejected(self.token(headers={"kid": "new"}), status=503)
        self.assertEqual(self.cache.keys, {})
        self.rejected(self.token(), status=503)
        self.assertEqual(self.fetch.call_count, 2)
        self.now += 59
        self.rejected(self.token(), status=503)
        self.now += 1
        self.fetch.side_effect = lambda: auth._parse_keys(json.dumps(self.document))
        self.valid()
        self.assertEqual(self.fetch.call_count, 3)

    def test_expired_cache_never_serves_stale_keys(self):
        self.valid()
        self.now += 300
        self.fetch.side_effect = auth._configuration_error()
        self.rejected(self.token(), status=503)
        self.assertEqual(self.cache.keys, {})

    def test_concurrent_requests_share_one_fetch_and_lock_wait_is_bounded(self):
        started, release = threading.Event(), threading.Event()
        def slow_fetch():
            started.set()
            self.assertTrue(release.wait(2))
            return auth._parse_keys(json.dumps(self.document))
        self.fetch.side_effect = slow_fetch
        token = "Bearer " + self.token()
        with ThreadPoolExecutor(max_workers=6) as pool:
            first = pool.submit(self.validator.authenticate, token)
            self.assertTrue(started.wait(1))
            rest = [pool.submit(self.validator.authenticate, token) for _ in range(5)]
            release.set()
            self.assertEqual([f.result(timeout=2) for f in [first, *rest]], ["synthetic-owner"] * 6)
        self.assertEqual(self.fetch.call_count, 1)
        with self.cache.lock, patch.object(auth, "_JWKS_TIMEOUT", 0.02):
            self.rejected(self.token(), status=503)


class IssuerTransportTests(_KeyFixture):
    def response(self, status=200, body=None, content_type="application/json", encoding="identity"):
        response = MagicMock()
        response.status = status
        response.read.return_value = json.dumps(self.document).encode() if body is None else body
        response.getheader.side_effect = lambda name, default=None: {"Content-Type": content_type, "Content-Encoding": encoding}.get(name, default)
        return response

    def test_fixed_issuer_url_tls_timeout_no_ambient_proxy_or_credentials(self):
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://attacker.example:8080", "ALL_PROXY": "http://attacker.example:8080"}), \
             patch.object(auth, "_PublicHTTPSConnection") as factory:
            cache = auth._IssuerKeys(ISSUER)
            factory.return_value.getresponse.return_value = response = self.response()
            self.assertIn("current", cache.get("current"))
            self.assertEqual(factory.call_args.args, ("tenant.example", 443))
            args = factory.call_args.kwargs
            self.assertIsNone(args["proxy"])
            self.assertEqual(args["timeout"], 5)
            self.assertGreater(args["deadline"], time.monotonic())
            self.assertTrue(args["context"].check_hostname)
            self.assertEqual(args["context"].verify_mode, ssl.CERT_REQUIRED)
            factory.return_value.request.assert_called_once_with("GET", "/.well-known/jwks.json", headers={
                "Accept": "application/jwk-set+json, application/json", "Accept-Encoding": "identity"})
            response.read.assert_called_once_with(auth._JWKS_LIMIT + 1)
            response.close.assert_called_once()
            factory.return_value.close.assert_called_once()
            self.assertEqual(auth._IssuerKeys(ISSUER, "http://127.0.0.1:7890").proxy, ("127.0.0.1", 7890))

    def test_reject_redirect_compression_bad_keys_and_oversize_responses(self):
        bad_documents = [b"invalid", b'{"keys":[]}', b'{"keys":[{"kty":"oct","k":"secret","kid":"x","alg":"HS256"}]}',
                         json.dumps({"keys": [self.document["keys"][0]] * 2}).encode(),
                         json.dumps({"keys": [{**self.document["keys"][0], "d": "private"}]}).encode(),
                         b"x" * (auth._JWKS_LIMIT + 1)]
        responses = [self.response(status=code) for code in (301, 302, 401, 404, 500)]
        responses += [self.response(content_type="text/html"), self.response(encoding="gzip")]
        responses += [self.response(body=body) for body in bad_documents]
        for response in responses:
            with self.subTest(status=response.status), patch.object(auth, "_PublicHTTPSConnection") as factory:
                factory.return_value.getresponse.return_value = response
                with self.assertRaises(auth.AuthError):
                    auth._IssuerKeys(ISSUER).get("current")
                factory.assert_called_once()
                factory.return_value.close.assert_called_once()

    def test_private_or_mixed_dns_is_rejected_before_connect_and_rechecked(self):
        public = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))
        for ip in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "198.18.0.1", "0.0.0.0"):
            private = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443))
            for answers in ([private], [public, private]):
                with patch.object(webhooks.socket, "getaddrinfo", return_value=answers), patch.object(webhooks.socket, "socket") as factory:
                    with self.assertRaises(auth.AuthError):
                        auth._IssuerKeys(ISSUER).get("current")
                    factory.assert_not_called()

    def test_get_uses_pinned_ip_original_sni_and_rejects_rebinding(self):
        cache = auth._IssuerKeys(ISSUER)
        body = json.dumps(self.document).encode()
        wire = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        public = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))
        private = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))
        tls = MagicMock()
        tls.send.side_effect = len
        tls.makefile.return_value = io.BytesIO(wire)
        with patch.object(webhooks.socket, "getaddrinfo", side_effect=[[public], [private]]) as dns, \
             patch.object(webhooks.socket, "socket") as sockets, patch.object(cache.context, "wrap_socket", return_value=tls) as wrap:
            cache._fetch()
            sockets.return_value.connect.assert_called_once_with(("8.8.8.8", 443))
            wrap.assert_called_once_with(sockets.return_value, server_hostname="tenant.example")
            sent = b"".join(call.args[0] for call in tls.send.call_args_list)
            self.assertIn(b"GET /.well-known/jwks.json HTTP/1.1", sent)
            self.assertIn(b"Host: tenant.example", sent)
            self.assertNotIn(b"Authorization", sent)
            with self.assertRaises(ValueError):
                cache._fetch()
            self.assertEqual(dns.call_count, 2)
            sockets.assert_called_once()

    def test_issuer_and_source_configuration_fail_offline(self):
        with patch.object(auth, "_PublicHTTPSConnection") as factory:
            for issuer in ("http://tenant.example/", "https://tenant.example/tenant", "https://user:pass@tenant.example/",
                           "https://tenant.example/?url=https://evil.example", "https://tenant.example:444/",
                           "https://tenant.example/#fragment", "https://tenant.example/?", "https://tenant.example/#"):
                with self.subTest(issuer=issuer), self.assertRaises(auth.AuthError):
                    auth._IssuerKeys(issuer)
            for options in ({}, {"jwks_from_issuer": "true"}, {"jwks_from_issuer": True, "jwks_path": "file"},
                            {"jwks_path": "file", "jwks_proxy_url": "http://127.0.0.1:7890"},
                            {"jwks_from_issuer": True, "jwks_proxy_url": "http://remote.example:7890"}):
                with self.subTest(options=options), self.assertRaises(auth.AuthError):
                    auth.Authenticator(**self.settings, **options)
            factory.assert_not_called()


class TunnelRouteTests(_KeyFixture):
    def test_transport_routes_discovery_and_identity_are_independent(self):
        self.validator = auth.Authenticator(**self.settings, jwks_path="synthetic-public.json", local_metadata_port=8765)
        bridge = MagicMock()
        bridge.rpc.return_value = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
        application = runtime.Application(bridge, self.validator, "synthetic", port=8765, worker=MagicMock(healthy=True))
        async def request(path, method="GET", token=None):
            messages = []
            headers = [(b"host", b"127.0.0.1:8765"), (b"content-type", b"application/json")]
            if token:
                headers.append((b"authorization", ("Bearer " + token).encode()))
            async def receive():
                return {"type": "http.request", "body": b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'}
            async def send(message):
                messages.append(message)
            await application({"type": "http", "path": path, "method": method, "headers": headers, "client": ("127.0.0.1", 1)}, receive, send)
            return messages[0]["status"], json.loads(messages[1]["body"]), dict(messages[0]["headers"])
        status, metadata, _ = asyncio.run(request("/.well-known/oauth-protected-resource/mcp"))
        self.assertEqual((status, metadata["resource"]), (200, RESOURCE))
        status, _, headers = asyncio.run(request("/mcp", "POST"))
        self.assertEqual(status, 401)
        self.assertIn(b'http://127.0.0.1:8765/.well-known/oauth-protected-resource/mcp', headers[b"www-authenticate"])
        self.assertEqual(asyncio.run(request("/mcp", "POST", self.token({"aud": [RESOURCE, ISSUER + "userinfo"]})))[0], 200)
        self.assertEqual(asyncio.run(request("/v1/mcp/tunnel_synthetic", "POST", self.token()))[0], 404)
        self.assertEqual(asyncio.run(request("/mcp", "POST", self.token({"aud": "http://127.0.0.1:8765/mcp"})))[0], 401)
        self.assertEqual(bridge.rpc.call_count, 1)
        self.assertEqual(json.loads(self.validator.binding_principal), [ISSUER, RESOURCE, "synthetic-owner"])
        other_port = auth.Authenticator(**self.settings, jwks_path="synthetic-public.json", local_metadata_port=9000)
        self.assertEqual(other_port.binding_principal, self.validator.binding_principal)

    def test_remote_configuration_check_is_offline_and_modes_are_explicit(self):
        config = {"public_resource_url": RESOURCE, "oauth_issuer": ISSUER, "owner_subject": "synthetic-owner",
                  "jwks_from_issuer": True, "secure_mcp_tunnel": True, "onebot_url": "http://127.0.0.1:3000",
                  "onebot_token_file": "synthetic.token", "state_key_file": "synthetic.key", "account_id": 1, "peer_id": 2}
        with patch.object(runtime, "read_secret_file", return_value=json.dumps(config)):
            loaded = runtime.load_config(Path("synthetic/config.json"))
        with patch.object(runtime, "read_secret_file", return_value="synthetic-only-" * 4), \
             patch.object(runtime, "StateCipher"), patch.object(runtime, "LoopbackOneBot"), \
             patch.object(auth, "_PublicHTTPSConnection") as factory:
            validator, _, _, _ = runtime.validate_configuration(loaded)
            self.assertEqual(validator.issuer_keys.keys, {})
            self.assertEqual(validator.metadata_url, "http://127.0.0.1:8765/.well-known/oauth-protected-resource/mcp")
            factory.assert_not_called()
        for changes in ({"jwks_file": "file"}, {"jwks_from_issuer": False}, {"jwks_from_issuer": "true"},
                        {"secure_mcp_tunnel": "true"}, {"secure_mcp_tunnel": False},
                        {"public_resource_url": RESOURCE + "?"}, {"jwks_proxy_url": "http://remote.example:8080"}):
            with self.subTest(changes=changes), patch.object(runtime, "read_secret_file", return_value=json.dumps({**config, **changes})):
                with self.assertRaises(ValueError):
                    runtime.load_config(Path("synthetic/config.json"))


if __name__ == "__main__":
    unittest.main()
