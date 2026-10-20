"""Synthetic integration tests. No QQ account, public callback, OAuth or dot."""

import hashlib
import hmac
import http.client
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from .core import Bridge, EVENT, RpcError, canonical
from .gateway import AmbiguousSend, GatewayRejected, LoopbackOneBot, decode_event
from .server import FIXTURE_TOKEN, make_fixture_server

SECRET = "whsec_" + "dGVzdC10ZXN0LXRlc3QtdGVzdC10ZXN0LXRlc3QtdGVzdA=="
SECOND = "whsec_" + "c2Vjb25kLXRlc3Qtc2Vjb25kLXRlc3Qtc2Vjb25kLXRlc3Q="


class Callback:
    def __init__(self):
        self.requests, self.status, self.challenge_ok = [], 204, True

    def post(self, url, body, headers):
        self.requests.append((url, body, headers))
        value = json.loads(body)
        if value.get("type") == "verification":
            return 200, json.dumps({"challenge": value["challenge"] if self.challenge_ok else "wrong"}).encode()
        return self.status, b""


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "test.sqlite3"
        self.now = [time.time()]
        self.callback = Callback()
        self.bridge = self.reopen()
        self.params = {"name": EVENT, "arguments": self.bridge.filters.copy(),
                       "delivery": {"mode": "webhook", "url": "https://receiver.example/callback", "secret": SECRET}}

    def reopen(self, **kwargs):
        return Bridge(self.path, principal="owner", account_id=100001, peer_id=100002,
                      clock=lambda: self.now[0], webhook_transport=self.callback, **kwargs)

    def record(self, **overrides):
        return {**self.bridge.filters, "message_id": "1", "timestamp": "2026-10-19T15:00:00+00:00", "text": "synthetic message", **overrides}

    def subscribe(self, **overrides):
        return self.bridge.subscribe("owner", {**self.params, **overrides})

    def test_subscription_idempotent_canonical_refresh_and_restart(self):
        first = self.subscribe(ttlMs=100000)
        self.now[0] += 1
        self.bridge = self.reopen()
        args = dict(reversed(list(self.params["arguments"].items())))
        second = self.subscribe(arguments=args, ttlMs=200000)
        self.assertEqual(first["id"], second["id"])
        self.assertNotEqual(first["refreshBefore"], second["refreshBefore"])
        self.assertEqual(len(self.callback.requests), 1)
        self.assertIsNone(second["cursor"])

    def test_previous_subscription_schema_is_migrated(self):
        old_path = Path(self.temp.name) / "old.sqlite3"
        with sqlite3.connect(old_path) as db:
            db.execute("CREATE TABLE subscriptions(id TEXT PRIMARY KEY,url TEXT NOT NULL,secret TEXT NOT NULL,old_secret TEXT,rotate_until REAL,expires REAL NOT NULL,verified_until REAL NOT NULL,active INTEGER NOT NULL)")
        db.close()  # sqlite3's context manager commits, but does not close on Windows.
        bridge = Bridge(old_path, principal="owner", account_id=100001, peer_id=100002, webhook_transport=self.callback)
        self.assertIn("id", bridge.subscribe("owner", self.params))

    def test_failed_verification_and_unconfigured_transport_fail_closed(self):
        self.callback.challenge_ok = False
        with self.assertRaises(RpcError) as failure:
            self.subscribe()
        self.assertEqual(failure.exception.code, -32015)
        self.assertEqual(self.bridge.status("owner")["active_subscriptions"], 0)
        self.bridge.webhook_transport = None
        with self.assertRaises(RpcError):
            self.subscribe()

    def test_one_chat_foreign_principal_and_filter_rejected(self):
        self.subscribe()
        with self.assertRaises(RpcError):
            self.bridge.subscribe("stranger", self.params)
        with self.assertRaises(RpcError):
            self.subscribe(arguments={**self.bridge.filters, "sender_id": "999999"})
        with self.assertRaises(RpcError):
            self.subscribe(delivery={**self.params["delivery"], "url": "https://other.example/callback"})

    def test_persistent_inbox_dedup_and_content_conflict(self):
        self.subscribe()
        first = self.bridge.ingest(self.record())
        self.bridge = self.reopen()
        self.assertTrue(self.bridge.ingest(self.record())["duplicate"])
        self.assertEqual(first["eventId"], self.bridge.ingest(self.record())["eventId"])
        with self.assertRaises(ValueError):
            self.bridge.ingest(self.record(text="different"))
        self.assertEqual(self.bridge.status("owner")["event_deliveries"], {"pending": 1})

    def test_event_retries_keep_id_and_body_but_refresh_signature(self):
        self.subscribe()
        self.bridge.ingest(self.record())
        self.callback.status = 503
        self.bridge.dispatch_event()
        first = self.callback.requests[-1]
        self.now[0] += 3
        self.bridge = self.reopen()
        self.callback.status = 204
        self.bridge.dispatch_event()
        second = self.callback.requests[-1]
        self.assertEqual(first[1], second[1])
        self.assertEqual(first[2]["webhook-id"], second[2]["webhook-id"])
        self.assertNotEqual(first[2]["webhook-signature"], second[2]["webhook-signature"])
        self.assertFalse(self.bridge.dispatch_event())

    def test_stale_attempt_cannot_overwrite_new_delivery_or_refreshed_subscription(self):
        self.subscribe()
        self.bridge.ingest(self.record())
        replacement = Callback()
        def late(url, body, headers):
            self.now[0] += 61
            self.bridge.webhook_transport = replacement
            self.bridge.dispatch_event()
            self.subscribe()
            return 410, b""
        with patch.object(self.callback, "post", side_effect=late):
            self.bridge.dispatch_event()
        self.assertEqual(self.bridge.status("owner")["event_deliveries"], {"accepted": 1})
        self.assertEqual(self.bridge.status("owner")["active_subscriptions"], 1)

    def test_terminal_responses_and_bounded_retry(self):
        self.subscribe()
        for index, status in enumerate((413, 400, 410)):
            with self.subTest(status=status):
                self.bridge.ingest(self.record(message_id=str(index)))
                self.callback.status = status
                self.bridge.dispatch_event()
                self.now[0] += 100
                self.assertFalse(self.bridge.dispatch_event())
        self.assertEqual(self.bridge.status("owner")["active_subscriptions"], 0)
        self.subscribe()
        self.bridge.ingest(self.record(message_id="100"))
        self.callback.status = 503
        for _ in range(5):
            self.assertTrue(self.bridge.dispatch_event())
            self.now[0] += 64
        self.assertFalse(self.bridge.dispatch_event())

    def test_rotation_uses_two_signatures(self):
        self.subscribe()
        self.subscribe(delivery={**self.params["delivery"], "secret": SECOND})
        self.bridge.ingest(self.record())
        self.bridge.dispatch_event()
        self.assertEqual(len(self.callback.requests[-1][2]["webhook-signature"].split(" ")), 2)

    def test_inflight_creation_or_refresh_cannot_revive_unsubscribe(self):
        def revoked(url, body, headers):
            self.bridge.unsubscribe("owner", self.params)
            self.bridge = self.reopen()  # Cancellation is persisted, not in-memory.
            return 200, canonical({"challenge": json.loads(body)["challenge"]}).encode()
        for refresh in (False, True):
            with self.subTest(refresh=refresh):
                if refresh:
                    self.subscribe()
                with patch.object(self.callback, "post", side_effect=revoked):
                    with self.assertRaises(RpcError):
                        self.subscribe(delivery={**self.params["delivery"], "secret": SECOND})
                self.assertEqual(self.bridge.status("owner")["active_subscriptions"], 0)

    def test_unsubscribe_expiry_and_revocation_stop_delivery(self):
        self.subscribe(ttlMs=1000)
        self.bridge.ingest(self.record())
        self.now[0] += 2
        self.subscribe()
        self.assertFalse(self.bridge.dispatch_event())
        self.bridge.ingest(self.record(message_id="2"))
        for _ in range(2):
            self.bridge.unsubscribe("owner", self.params)
        self.assertFalse(self.bridge.dispatch_event())
        self.bridge.revoke()
        with self.assertRaises(RpcError):
            self.bridge.ingest(self.record(message_id="3"))
        with self.assertRaises(RpcError):
            self.subscribe()

    def test_reply_is_bound_persistent_idempotent_and_ambiguous_safe(self):
        event_id = self.bridge.ingest(self.record())["eventId"]
        args = {"event_id": event_id, "text": "synthetic response"}
        self.assertFalse(self.bridge.reply("owner", args)["sent"])
        self.bridge = self.reopen()
        self.assertEqual(self.bridge.reply("owner", args)["state"], "pending")
        for invalid in ({**args, "user_id": "999999"}, {**args, "text": "different"}, {**args, "event_id": "unknown"}):
            with self.assertRaises(RpcError):
                self.bridge.reply("owner", invalid)
        class Gateway:
            count = 0
            account_id, peer_id = 100001, 100002
            def send_text(self, text):
                self.count += 1
                raise AmbiguousSend("timeout after send")
        gateway = Gateway()
        self.bridge.gateway = gateway
        self.bridge.dispatch_reply()
        self.bridge = self.reopen(gateway=gateway)
        self.assertFalse(self.bridge.dispatch_reply())
        self.assertEqual(self.bridge.reply("owner", args)["state"], "uncertain")
        self.assertEqual(gateway.count, 1)

    def test_crash_during_send_never_retries_and_binding_is_immutable(self):
        event_id = self.bridge.ingest(self.record())["eventId"]
        self.bridge.reply("owner", {"event_id": event_id, "text": "response"})
        with self.bridge.db() as db:
            db.execute("UPDATE replies SET state='sending'")
        self.bridge = self.reopen()
        self.bridge.recover_interrupted_replies()
        self.assertEqual(self.bridge.status("owner")["replies"], {"uncertain": 1})
        with self.assertRaises(ValueError):
            Bridge(self.path, principal="owner", account_id=100001, peer_id=999999)
        mismatch = LoopbackOneBot("http://127.0.0.1:3000", "fixture", account_id=100001, peer_id=999999)
        with self.assertRaises(ValueError):
            self.reopen(gateway=mismatch)
        self.bridge.gateway = mismatch
        with self.assertRaises(ValueError):
            self.bridge.dispatch_reply()

    def test_rpc_catalog_and_no_general_execution_tool(self):
        def rpc(method, params=None):
            return self.bridge.rpc("owner", {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
        self.assertEqual(rpc("server/discover")["result"]["supportedVersions"], ["2026-07-28"])
        self.assertEqual(len(rpc("events/list")["result"]["events"]), 1)
        from .media_tools import TOOL_SCOPES
        self.assertEqual({x["name"] for x in rpc("tools/list")["result"]["tools"]}, {"bridge_status", "qq_reply", *TOOL_SCOPES})
        self.assertEqual(rpc("tools/call", {"name": "shell", "arguments": {}})["error"]["code"], -32602)
        self.assertIn("error", self.bridge.rpc("owner", []))
        self.assertIsNone(self.bridge.rpc("owner", {"jsonrpc": "2.0", "id": {}, "method": "tools/list"})["id"])


class GatewayTests(unittest.TestCase):
    def test_malformed_send_outcomes_are_uncertain_and_target_is_fixed(self):
        gateway = LoopbackOneBot("http://127.0.0.1:3000", "fixture", account_id=100001, peer_id=100002)
        for malformed in (None, [], {}, {"status": "ok", "retcode": 4}, {"status": "failed", "retcode": 0}):
            with self.subTest(malformed=malformed), patch("bridge_service.gateway.http.client.HTTPConnection") as factory:
                response = factory.return_value.getresponse.return_value
                response.status, response.read.return_value = 200, json.dumps(malformed).encode()
                with self.assertRaises(AmbiguousSend):
                    gateway._call("send_private_msg", {})
        with patch.object(gateway, "_call", side_effect=[{"user_id": 100001}, {"message_id": 123}]) as call:
            self.assertEqual(gateway.send_text("[CQ:fake]"), "123")
            self.assertEqual(call.call_args.args, ("send_private_msg", {
                "user_id": 100002, "message": [{"type": "text", "data": {"text": "[CQ:fake]"}}], "auto_escape": True}))
        with patch.object(gateway, "_call", return_value={"user_id": 999999}) as call:
            with self.assertRaises(GatewayRejected):
                gateway.send_text("response")
            self.assertEqual(call.call_count, 1)

    def test_real_onebot_shape_and_signature_but_synthetic_payload(self):
        now = int(time.time())
        event = {"post_type": "message", "message_type": "private", "sub_type": "friend",
                 "self_id": 100001, "user_id": 100002, "message_id": 7, "time": now,
                 "sender": {"user_id": 100002}, "message": [{"type": "text", "data": {"text": "[CQ:fake] literal"}}]}
        def decode(value, tamper=False):
            body = canonical(value).encode()
            signature = "sha1=" + hmac.new(b"fixture", body, hashlib.sha1).hexdigest()
            return decode_event(body, {"X-Self-ID": "100001", "X-Signature": signature + ("x" if tamper else "")},
                                "fixture", account_id=100001, peer_id=100002, now=now)
        self.assertEqual(decode(event)["text"], "[CQ:fake] literal")
        for changes in ({"post_type": "message_sent"}, {"sub_type": "group"}, {"user_id": 100003},
                        {"self_id": 100003}, {"time": now - 301}, {"message": [{"type": "image", "data": {"url": "https://example.com/x"}}]}):
            with self.subTest(changes=changes), self.assertRaises(GatewayRejected):
                decode({**event, **changes})
        with self.assertRaises(GatewayRejected):
            decode(event, tamper=True)

    def test_gateway_target_configuration_is_loopback_only(self):
        for url in ("http://example.com:3000", "http://127.0.0.1:3000/path", "http://user:pass@127.0.0.1:3000", "http://10.0.0.1:3000"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                LoopbackOneBot(url, "fixture", account_id=100001, peer_id=100002)

    def test_http_fixture_auth_origin_and_default_no_network(self):
        server = make_fixture_server()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            def request(auth=None, origin=None):
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port)
                headers = {"Content-Type": "application/json"}
                if auth: headers["Authorization"] = auth
                if origin: headers["Origin"] = origin
                conn.request("POST", "/mcp", canonical({"jsonrpc": "2.0", "id": 1, "method": "server/discover"}), headers)
                response = conn.getresponse()
                result = response.status, json.loads(response.read())
                conn.close()
                return result
            self.assertEqual(request()[0], 401)
            self.assertEqual(request("Bearer " + FIXTURE_TOKEN)[0], 200)
            self.assertEqual(request("Bearer " + FIXTURE_TOKEN, "https://evil.example")[0], 403)
            self.assertIsNone(server.bridge.gateway)
            self.assertIsNone(server.bridge.webhook_transport)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
            server.fixture_directory.cleanup()


if __name__ == "__main__":
    unittest.main()
