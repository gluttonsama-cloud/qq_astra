"""Configured-path tests with ephemeral synthetic keys and in-memory transports.

No QQ login, production credential, public listener or external send is used.
"""

import asyncio
import hashlib
import hmac
import json
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa

from .core import EVENT, RpcError, canonical
from .runtime import QueueWorker, RateLimit, create_application, load_config, validate_configuration
from .state import StateError
from .test_service import Callback, SECRET


class FakeGateway:
    account_id, peer_id = 100001, 100002

    def __init__(self):
        self.sent = []

    def send_text(self, text):
        self.sent.append(text)
        return "synthetic-ack"


class RuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-qq-runtime-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key())),
               "alg": "RS256", "kid": "synthetic", "use": "sig"}
        (root / "public-jwks.json").write_text(json.dumps({"keys": [jwk]}))
        self.secret = "synthetic-only-onebot-secret-00000000"
        # Test-only, short-lived encryption key; this is not a provisioning path.
        for name, value in (("onebot.token", self.secret), ("state.key", Fernet.generate_key().decode())):
            path = root / name
            path.write_text(value)
            path.chmod(0o600)
        self.config_path = root / "config.json"
        self.config_path.write_text(json.dumps({
            "public_resource_url": "https://bridge.example/mcp", "oauth_issuer": "https://issuer.example/",
            "owner_subject": "synthetic-owner", "jwks_file": "public-jwks.json",
            "onebot_url": "http://127.0.0.1:3000", "onebot_token_file": "onebot.token",
            "state_key_file": "state.key", "state_dir": "state", "account_id": 100001, "peer_id": 100002}))
        self.config_path.chmod(0o600)
        self.config = load_config(self.config_path)
        self.app = create_application(self.config)
        self.callback, self.gateway = Callback(), FakeGateway()
        self.app.bridge.webhook_transport, self.app.bridge.gateway = self.callback, self.gateway
        self.events, self.lifecycle_messages = asyncio.Queue(), []
        async def send(message):
            self.lifecycle_messages.append(message)
        self.lifecycle = asyncio.create_task(self.app({"type": "lifespan"}, self.events.get, send))
        await self.events.put({"type": "lifespan.startup"})
        await self.until(lambda: bool(self.lifecycle_messages))
        self.assertEqual(self.lifecycle_messages[0]["type"], "lifespan.startup.complete")

    async def asyncTearDown(self):
        await self.shutdown()

    async def shutdown(self):
        if not self.lifecycle.done():
            await self.events.put({"type": "lifespan.shutdown"})
            await asyncio.wait_for(self.lifecycle, 5)
        self.app.worker.stop()
        self.app.state.close()

    async def until(self, predicate):
        deadline = time.monotonic() + 3
        while not predicate():
            if time.monotonic() >= deadline:
                self.fail("local worker did not reach the expected state")
            await asyncio.sleep(0.01)

    def token(self, scopes="qq:read qq:events qq:reply", **changes):
        now = int(time.time())
        claims = {"iss": self.config["oauth_issuer"], "aud": self.config["public_resource_url"],
                  "sub": "synthetic-owner", "iat": now - 1, "exp": now + 300, "scope": scopes, **changes}
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"typ": "at+jwt", "kid": "synthetic"})

    async def request(self, path="/mcp", value=None, *, method="POST", token=None, headers=()):
        body = canonical(value).encode() if value is not None else b""
        messages = []
        host = b"127.0.0.1:8765" if path == "/onebot/events" else b"bridge.example"
        default_headers = [(b"host", host), (b"content-type", b"application/json")]
        if token:
            default_headers.append((b"authorization", ("Bearer " + token).encode()))
        default_headers.extend(headers)
        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}
        async def send(message):
            messages.append(message)
        await self.app({"type": "http", "path": path, "method": method,
                        "headers": default_headers, "client": ("127.0.0.1", 1234)}, receive, send)
        return messages[0]["status"], json.loads(messages[1]["body"]), dict(messages[0]["headers"])

    def subscription(self):
        return {"name": EVENT, "arguments": self.app.bridge.filters.copy(), "ttlMs": 86400000,
                "delivery": {"mode": "webhook", "url": "https://receiver.example/callback", "secret": SECRET}}

    async def test_configured_auth_metadata_scope_limits_and_fail_closed(self):
        with patch("socket.socket.connect", side_effect=AssertionError("unexpected network")):
            validate_configuration(self.config)
        status, data, _ = await self.request("/.well-known/oauth-protected-resource/mcp", method="GET")
        self.assertEqual((status, data["resource"]), (200, self.config["public_resource_url"]))
        rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        status, _, headers = await self.request(value=rpc)
        self.assertEqual(status, 401)
        self.assertIn(b"resource_metadata=", headers[b"www-authenticate"])
        self.assertEqual((await self.request(value=rpc, token=self.token(sub="stranger")))[0], 401)
        self.assertEqual((await self.request(value=rpc, token=self.token("qq:read")))[0], 200)
        rpc.update(method="tools/call", params={"name": "qq_reply", "arguments": {}})
        self.assertEqual((await self.request(value=rpc, token=self.token("qq:read")))[0], 403)
        self.assertEqual((await self.request(value=rpc, token=self.token(), headers=[(b"origin", b"https://stranger.example")]))[0], 403)
        self.app.limits["mcp"] = RateLimit(rate=0, burst=0)
        self.assertEqual((await self.request(value=rpc, token=self.token()))[0], 429)
        self.config_path.chmod(0o644)
        with self.assertRaises(StateError):
            load_config(self.config_path)
        self.config_path.chmod(0o600)
        with self.assertRaises(ValueError):
            validate_configuration({**self.config, "onebot_url": "https://remote.example"})

    async def test_signed_message_to_callback_reply_restart_and_encrypted_backup(self):
        token = self.token()
        rpc = {"jsonrpc": "2.0", "id": 1, "method": "events/subscribe", "params": self.subscription()}
        status, result, _ = await self.request(value=rpc, token=token)
        self.assertEqual(status, 200)
        expires = datetime.fromisoformat(result["result"]["refreshBefore"]).timestamp()
        self.assertLessEqual(expires, jwt.decode(token, options={"verify_signature": False})["exp"])
        event = {"post_type": "message", "message_type": "private", "sub_type": "friend", "self_id": 100001,
                 "user_id": 100002, "sender": {"user_id": 100002}, "message_id": 77, "time": int(time.time()),
                 "message": [{"type": "text", "data": {"text": "unique-synthetic-private-message"}}]}
        signature = "sha1=" + hmac.new(self.secret.encode(), canonical(event).encode(), hashlib.sha1).hexdigest()
        wire_headers = [(b"x-self-id", b"100001"), (b"x-signature", signature.encode())]
        for _ in range(2):
            self.assertEqual((await self.request("/onebot/events", event, headers=wire_headers))[0], 200)
        await self.until(lambda: self.app.bridge.status(self.app.auth.binding_principal)["event_deliveries"] == {"accepted": 1})
        event_id = json.loads(self.callback.requests[-1][1])["eventId"]
        args = {"event_id": event_id, "text": "unique-synthetic-private-reply"}
        rpc.update(method="tools/call", params={"name": "qq_reply", "arguments": args})
        for _ in range(2):
            self.assertEqual((await self.request(value=rpc, token=token))[0], 200)
        await self.until(lambda: self.app.bridge.status(self.app.auth.binding_principal)["replies"] == {"confirmed": 1})
        self.assertEqual(self.gateway.sent, [args["text"]])
        rpc["params"]["arguments"] = {**args, "user_id": "999999"}
        self.assertIn("error", (await self.request(value=rpc, token=token))[1])
        await self.shutdown()
        self.assertEqual(self.lifecycle_messages[-1]["type"], "lifespan.shutdown.complete")
        self.assertFalse(self.app.worker.healthy)
        state = Path(self.config["state_dir"])
        self.assertTrue((state / "bridge.backup.sqlite3").exists())
        for path in state.glob("*.sqlite3*"):
            raw = path.read_bytes()
            for private in (args["text"], "unique-synthetic-private-message", SECRET, "synthetic-owner"):
                self.assertNotIn(private.encode(), raw)
        reopened = create_application(self.config)
        try:
            self.assertEqual(reopened.bridge.reply(reopened.auth.binding_principal, args)["state"], "confirmed")
            self.assertTrue(reopened.bridge.status(reopened.auth.binding_principal)["encrypted_state"])
        finally:
            reopened.state.close()
        for changes in ({"oauth_issuer": "https://different-issuer.example/"},
                        {"public_resource_url": "https://different-resource.example/mcp"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                create_application({**self.config, **changes})

    async def test_token_lease_cannot_be_extended_by_challenge_and_worker_failure_is_unready(self):
        now = time.time()
        self.app.bridge.clock = lambda: now
        def slow_verification(url, body, headers):
            self.app.bridge.clock = lambda: now + 2
            return 200, canonical({"challenge": json.loads(body)["challenge"]}).encode()
        with patch.object(self.callback, "post", side_effect=slow_verification):
            with self.assertRaises(RpcError):
                self.app.bridge.subscribe(self.app.auth.binding_principal, self.subscription(), access_deadline=now + 1)
        self.assertEqual(self.app.bridge.status(self.app.auth.binding_principal)["active_subscriptions"], 0)
        class BrokenBridge:
            def recover_interrupted_replies(self):
                pass
            def dispatch_reply(self):
                raise RuntimeError("synthetic worker failure")
        broken = QueueWorker(BrokenBridge())
        broken.start()
        await self.until(lambda: broken.failed)
        self.assertFalse(broken.healthy)
        broken.stop()


if __name__ == "__main__":
    unittest.main()
