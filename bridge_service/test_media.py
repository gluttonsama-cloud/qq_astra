"""Synthetic media/identity/outbox checks: no QQ account, public network or files."""

import asyncio
import base64
import hashlib
import hmac
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet
from PIL import Image

from . import media
from .core import Bridge, RpcError, canonical
from .gateway import AmbiguousSend, GatewayRejected, LoopbackOneBot, decode_event
from .media_tools import MEDIA_TOOLS, TOOL_SCOPES
from .operations import OUTBOX_TTL, SOURCE_TTL
from .runtime import Application
from .state import StateCipher
from .test_oauth_tunnel import _KeyFixture

OWNER, ACCOUNT, PEER = "synthetic-owner", 100001, 100002
SECRET = "synthetic-only-media-gateway-secret"
QQ_URL = "https://multimedia.nt.qq.com/download?fileid=fixture&appid=1406&rkey=synthetic-old"
FILE = {"file_id": "file_synthetic", "download_url": "https://uploads.example/synthetic.png?token=fixture", "mime_type": "image/png", "file_name": "fixture.png"}


def picture(fmt="PNG", frames=1, size=(3, 2)):
    output = io.BytesIO()
    images = [Image.new("RGB", size, (i * 80 % 255, 10, 20)) for i in range(frames)]
    images[0].save(output, format=fmt, **({"save_all": True, "append_images": images[1:], "duration": 100, "loop": 0} if frames > 1 else {}))
    return output.getvalue()


class FixtureFetcher:
    file_hosts = frozenset({"uploads.example"})
    def __init__(self):
        self.raw, self.calls = picture(), []
    def fetch(self, url, *, qq=False, declared=None):
        media.source_url(url, media.QQ_HOSTS if qq else self.file_hosts, qq=qq)
        self.calls.append(url)
        media.inspect_image(self.raw, declared)
        return self.raw


class FixtureQQ(LoopbackOneBot):
    def __init__(self):
        super().__init__("http://127.0.0.1:3000", SECRET, account_id=ACCOUNT, peer_id=PEER)
        self.logged_in, self.writes, self.reads, self.ambiguous = ACCOUNT, [], [], False
        self.image = QQ_URL.replace("synthetic-old", "synthetic-new")
    def _call(self, action, params):
        if action == "get_login_info":
            return {"user_id": self.logged_in}
        if action == "get_image":
            self.reads.append((action, params))
            return {"url": self.image}
        if action == "search_sys_faces":
            return {"faces": [{"q_sid": "14", "q_des": "synthetic smile"}]}
        if action == "fetch_face_entity":
            return {"q_sid": "14"} if params["face_id"] == 14 else None
        if action == "fetch_custom_face_detail":
            return [{"emoji_id": "saved_fixture", "desc": "synthetic saved sticker"}]
        self.writes.append((action, params))
        if self.ambiguous:
            raise AmbiguousSend("synthetic lost response")
        return {"tid": "synthetic-post"} if action == "send_qzone_msg" else {"message_id": 900 + len(self.writes)}


class MediaFixture(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="synthetic-media-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "state.sqlite3"
        self.now = [time.time()]
        self.fetcher, self.qq = FixtureFetcher(), FixtureQQ()
        self.cipher = StateCipher(Fernet.generate_key().decode())
        self.bridge = self.open()
    def open(self):
        return Bridge(self.path, principal=OWNER, account_id=ACCOUNT, peer_id=PEER,
                      cipher=self.cipher, gateway=self.qq, media_fetcher=self.fetcher, clock=lambda: self.now[0])
    def ingest(self, segments=None, **changes):
        event = {"post_type": "message", "message_type": "private", "sub_type": "friend", "self_id": ACCOUNT,
                 "user_id": PEER, "sender": {"user_id": PEER, "nickname": "untrusted nickname"}, "message_id": 12,
                 "time": int(self.now[0]), "message": segments or [{"type": "image", "data": {"file": "fixture.png", "url": QQ_URL}}], **changes}
        raw = canonical(event).encode()
        record = decode_event(raw, {"X-Self-ID": str(ACCOUNT), "X-Signature": "sha1=" + hmac.new(SECRET.encode(), raw, hashlib.sha1).hexdigest()},
                              SECRET, account_id=ACCOUNT, peer_id=PEER, now=self.now[0])
        response = self.bridge.ingest(record)
        with self.bridge.db() as db:
            stored = db.execute("SELECT body FROM inbox WHERE id=?", (response["eventId"],)).fetchone()[0]
        body = json.loads(self.bridge._open(stored))
        refs = {"event_id": body["eventId"], "attachment_id": body["data"]["attachments"][0]["attachment_id"]} if "attachments" in body["data"] else {}
        return body, refs
    def call(self, name, args, principal=OWNER):
        return self.bridge.rpc(principal, {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}})
    def value(self, name, args):
        result = self.call(name, args)
        self.assertNotIn("error", result)
        self.assertFalse(result["result"]["isError"], result)
        return json.loads(result["result"]["content"][0]["text"])


class ImageValidationTests(unittest.TestCase):
    def test_real_formats_mime_and_preview_not_url(self):
        for fmt in ("PNG", "JPEG", "WEBP", "GIF"):
            raw = picture(fmt, 2 if fmt == "GIF" else 1)
            info, preview = media.inspect_image(raw, preview=True)
            self.assertEqual(info["frames"], 2 if fmt == "GIF" else 1)
            self.assertEqual(preview["type"], "image")
            self.assertEqual(Image.open(io.BytesIO(base64.b64decode(preview["data"]))).format, "PNG")
        for raw, mime in ((b"<svg/>", "image/png"), (picture(), "image/jpeg"), (picture()[:20], "image/png"), (b"a" * (media.MAX_IMAGE_BYTES + 1), None)):
            with self.assertRaises(media.MediaError):
                media.inspect_image(raw, mime)
        with patch.object(media, "MAX_PIXELS", 2), self.assertRaises(media.MediaError):
            media.inspect_image(picture())
        with patch.object(media, "MAX_FRAMES", 1), self.assertRaises(media.MediaError):
            media.inspect_image(picture("GIF", 2))

    def test_file_inputs_reject_paths_arbitrary_origins_and_false_mimes(self):
        for value in ("C:\\private.png", {"file_id": "file_x", "download_url": "file:///C:/private.png"},
                      {**FILE, "download_url": "https://evil.example/a"}, {**FILE, "path": "C:/private.png"},
                      {**FILE, "mime_type": "image/svg+xml"}, {**FILE, "file_id": "../../x"}):
            with self.assertRaises(media.MediaError):
                media.validate_file(value, {"uploads.example"})
        for url in ("https://uploads.example@127.0.0.1/x", "https://uploads.example:8443/x", "https://uploads.example/x#frag", "http://uploads.example/x"):
            with self.assertRaises(media.MediaError):
                media.source_url(url, {"uploads.example"})
        with self.assertRaises(media.MediaError):
            media.source_url(FILE["download_url"], set())

    def test_get_transport_reuses_pinned_connection_and_rejects_redirects_lengths(self):
        fetcher = media.ImageFetcher(download_hosts=["uploads.example"])
        for code, headers, body, success in (
            (200, {"Content-Type": "image/png"}, picture(), True),
            (302, {"Content-Type": "image/png", "Location": "http://127.0.0.1/"}, picture(), False),
            (200, {"Content-Type": "image/png", "Content-Encoding": "gzip"}, picture(), False),
            (200, {"Content-Type": "image/png", "Content-Length": "99"}, picture(), False),
            (200, {"Content-Type": "image/png"}, b"not-an-image", False)):
            conn, response = MagicMock(), MagicMock()
            response.status, response.read.return_value = code, body
            response.getheader.side_effect = lambda key, default=None: headers.get(key, default)
            conn.getresponse.return_value = response
            with patch.object(media, "_PublicHTTPSConnection", return_value=conn) as factory:
                if success:
                    self.assertEqual(fetcher.fetch(FILE["download_url"]), body)
                    self.assertEqual(factory.call_args.args, ("uploads.example", 443))
                    self.assertEqual(conn.request.call_args.args[:2], ("GET", "/synthetic.png?token=fixture"))
                else:
                    with self.assertRaises(media.MediaError):
                        fetcher.fetch(FILE["download_url"])
                self.assertEqual(conn.request.call_count, 1)
                self.assertTrue(conn.close.called)


class MediaFlowTests(MediaFixture):
    def test_bounded_outbox_and_incomplete_market_face_fail_closed(self):
        for name in ([], {}, None):
            self.assertIn("error", self.call(name, {}))
        _, refs = self.ingest([{"type": "image", "data": {"emoji_id": "b" * 32}}])
        self.assertEqual(self.call("qq_read_image", refs)["result"]["content"][1]["type"], "image")
        self.assertTrue(self.call("qq_send_market_face", {"request_id": "market_missing", **refs})["result"]["isError"])
        with patch("bridge_service.operations.MAX_PENDING_BYTES", 1):
            self.assertTrue(self.call("qq_send_image", {"request_id": "too_large", "file": FILE, "as_sticker": False})["result"]["isError"])
        self.assertFalse(self.bridge.operations.dispatch())
        self.assertEqual(self.qq.writes, [])

    def test_admission_bound_identity_visual_result_and_no_source_url_leak(self):
        body, refs = self.ingest()
        self.assertNotIn("synthetic-old", canonical(body))
        identity = body["data"]["sender_identity"]
        self.assertEqual((identity["role"], identity["qq_id"], identity["bot_qq_id"]), ("bound_owner", str(PEER), str(ACCOUNT)))
        self.assertEqual(identity, self.bridge.sender_identity())
        result = self.call("qq_read_image", refs)["result"]
        self.assertEqual(result["content"][1]["type"], "image")
        self.assertNotIn("rkey", canonical(result))
        self.assertEqual(self.qq.reads[0], ("get_image", {"file": "fixture.png"}))
        for changes in ({"self_id": PEER}, {"user_id": 777}, {"sender": {"user_id": 777}}, {"message_type": "group"}):
            with self.assertRaises(GatewayRejected):
                self.ingest(**changes)
        self.assertIn("error", self.call("qq_read_image", refs, principal="stranger"))
        self.assertTrue(self.call("qq_read_image", {**refs, "event_id": "qq_other"})["result"]["isError"])
        self.qq.image = "https://multimedia.nt.qq.com/download?fileid=other&appid=1406&rkey=synthetic-new"
        self.assertTrue(self.call("qq_read_image", refs)["result"]["isError"])

    def test_image_gif_and_saved_sticker_use_real_adapter_shapes(self):
        for number, fmt in enumerate(("PNG", "GIF")):
            self.fetcher.raw = picture(fmt, 2 if fmt == "GIF" else 1)
            file = {**FILE, "file_id": f"file_{fmt}", "mime_type": media.MIMES[fmt]}
            args = {"request_id": f"image_{number:03}", "file": file, "as_sticker": True}
            self.assertEqual(self.value("qq_send_image", args)["state"], "pending")
            self.bridge.operations.dispatch()
            action, data = self.qq.writes[-1]
            self.assertEqual((action, data["user_id"]), ("send_private_msg", PEER))
            segment = data["message"][0]
            self.assertEqual(segment["data"]["sub_type"], 1)
            self.assertEqual(base64.b64decode(segment["data"]["file"].removeprefix("base64://")), self.fetcher.raw)
            count = len(self.qq.writes)
            self.assertEqual(self.value("qq_send_image", {**args, "file": {**file, "download_url": "https://uploads.example/renewed"}})["state"], "confirmed")
            self.assertFalse(self.bridge.operations.dispatch())
            self.assertEqual(len(self.qq.writes), count)
        listed = self.value("qq_list_custom_faces", {"count": 10})
        self.assertEqual(listed["stickers"][0]["emoji_id"], "saved_fixture")
        args = {"request_id": "saved_001", "emoji_id": "saved_fixture"}
        self.value("qq_send_custom_face", args)
        self.bridge.operations.dispatch()
        self.assertEqual(self.qq.writes[-1], ("send_custom_face", {"user_id": PEER, "emoji_id": "saved_fixture"}))
        self.assertTrue(self.call("qq_send_custom_face", {**args, "request_id": "saved_bad", "emoji_id": "unknown"})["result"]["isError"])

    def test_faces_market_fields_and_explicit_space_audience(self):
        self.assertEqual(self.value("qq_list_faces", {"query": "smile"})["faces"][0]["face_id"], 14)
        self.value("qq_send_face", {"request_id": "face_001", "face_id": 14})
        self.bridge.operations.dispatch()
        self.assertEqual(self.qq.writes[-1][1]["message"], [{"type": "face", "data": {"id": "14"}}])
        _, refs = self.ingest([{"type": "mface", "data": {"emoji_id": "a" * 32, "emoji_package_id": 10, "key": "synthetic"}}])
        self.value("qq_send_market_face", {"request_id": "market_01", **refs})
        self.bridge.operations.dispatch()
        self.assertEqual(self.qq.writes[-1][1]["message"][0]["type"], "mface")
        args = {"request_id": "qzone_001", "content": "synthetic post", "images": [], "ugc_right": 64, "target_uins": []}
        for bad in ({k: v for k, v in args.items() if k != "ugc_right"}, {**args, "ugc_right": 16}, {**args, "target_uins": [PEER]}, {**args, "user_id": PEER}):
            self.assertTrue(self.call("qq_publish_qzone", bad)["result"]["isError"])
        self.value("qq_publish_qzone", args)
        self.bridge.operations.dispatch()
        self.assertEqual(self.qq.writes[-1], ("send_qzone_msg", {"content": "synthetic post", "images": [], "ugc_right": 64, "target_uins": []}))
        args = {**args, "request_id": "qzone_002", "ugc_right": 16, "target_uins": [PEER], "images": [FILE]}
        self.value("qq_publish_qzone", args)
        self.bridge.operations.dispatch()
        self.assertTrue(self.qq.writes[-1][1]["images"][0].startswith("base64://"))

    def test_durable_uncertain_no_replay_expiry_cleanup_and_revocation(self):
        _, refs = self.ingest()
        args = {"request_id": "send_001", "file": FILE, "as_sticker": False}
        self.value("qq_send_image", args)
        self.qq.ambiguous = True
        self.bridge.operations.dispatch()
        self.bridge = self.open()
        self.bridge.recover_interrupted_replies()
        self.assertEqual(self.value("qq_send_image", args)["state"], "uncertain")
        self.assertFalse(self.bridge.operations.dispatch())
        self.assertEqual(len(self.qq.writes), 1)
        self.assertTrue(self.call("qq_send_image", {**args, "as_sticker": True})["result"]["isError"])
        self.value("qq_send_image", {**args, "request_id": "send_002"})
        self.now[0] += OUTBOX_TTL + 1
        self.assertFalse(self.bridge.operations.dispatch())
        self.assertEqual(self.value("qq_operation_status", {"request_id": "send_002"})["state"], "failed")
        with self.bridge.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM operations WHERE payload IS NOT NULL").fetchone()[0], 0)
        self.now[0] += SOURCE_TTL
        self.assertTrue(self.call("qq_read_image", refs)["result"]["isError"])
        self.bridge.revoke()
        self.assertIn("error", self.call("qq_list_custom_faces", {"count": 10}))

    def test_account_switch_interrupted_send_and_no_ingress_side_effect(self):
        self.ingest()
        self.assertFalse(self.bridge.operations.dispatch())
        self.assertEqual(self.qq.writes, [])
        args = {"request_id": "face_002", "face_id": 14}
        self.value("qq_send_face", args)
        self.qq.logged_in = 777
        self.bridge.operations.dispatch()
        self.assertEqual(self.value("qq_operation_status", {"request_id": "face_002"})["state"], "failed")
        self.assertEqual(self.qq.writes, [])
        self.qq.logged_in = ACCOUNT
        self.value("qq_send_face", {**args, "request_id": "face_003"})
        with self.bridge.db() as db:
            db.execute("UPDATE operations SET state='sending' WHERE request_id='face_003'")
        self.bridge = self.open()
        self.bridge.recover_interrupted_replies()
        self.assertEqual(self.value("qq_operation_status", {"request_id": "face_003"})["state"], "uncertain")
        self.assertFalse(self.bridge.operations.dispatch())
        for path in Path(self.directory.name).glob("*.sqlite3*"):
            self.assertNotIn(b"synthetic-old", path.read_bytes())
            self.assertNotIn(b"bound_owner", path.read_bytes())


class MediaScopeTests(_KeyFixture):
    def test_explicit_new_scopes_and_file_contract(self):
        bridge = MagicMock()
        bridge.rpc.return_value = {"jsonrpc": "2.0", "id": 1, "result": {"content": []}}
        application = Application(bridge, self.validator, SECRET, port=8765, worker=MagicMock(healthy=True))
        async def call(name, scope):
            output = []
            body = canonical({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": {}}}).encode()
            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}
            async def send(value):
                output.append(value)
            await application({"type": "http", "path": "/mcp", "method": "POST", "client": ("127.0.0.1", 4), "headers": [
                (b"host", b"127.0.0.1:8765"), (b"content-type", b"application/json"),
                (b"authorization", ("Bearer " + self.token({"scope": scope})).encode())]}, receive, send)
            return json.loads(output[1]["body"])
        for name, scope in TOOL_SCOPES.items():
            if scope == "qq:read":
                continue
            with self.subTest(name=name):
                bridge.rpc.reset_mock()
                rejected = asyncio.run(call(name, "qq:read qq:events qq:reply"))
                self.assertTrue(rejected["result"]["isError"])
                self.assertFalse(bridge.rpc.called)
                asyncio.run(call(name, scope))
                self.assertTrue(bridge.rpc.called)
            application.limits["mcp"].tokens = 30
        for name in ([], {}, None):
            bridge.rpc.reset_mock()
            asyncio.run(call(name, "qq:read"))
            self.assertTrue(bridge.rpc.called)  # RPC layer handles invalid names.
        for tool in MEDIA_TOOLS:
            for field in tool.get("_meta", {}).get("openai/fileParams", []):
                schema = tool["inputSchema"]["properties"][field]
                schema = schema.get("items", schema)
                self.assertEqual(set(schema["required"]), {"download_url", "file_id"})
                self.assertEqual(set(schema["properties"]), {"download_url", "file_id", "mime_type", "file_name"})
        publish = next(x for x in MEDIA_TOOLS if x["name"] == "qq_publish_qzone")
        self.assertFalse(publish["annotations"]["readOnlyHint"])
        self.assertIn("ugc_right", publish["inputSchema"]["required"])


if __name__ == "__main__":
    unittest.main()
