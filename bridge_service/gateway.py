"""Bounded SnowLuma v2.0.3 OneBot adapter. No login or arbitrary action tool.

Wire references: SnowLuma/SnowLuma tag v2.0.3, packages/onebot/src/
network/http-post-adapter.ts, network/utils.ts, event-converter/to-message.ts,
and actions/message.ts. HMAC-SHA1 here is OneBot's existing wire protocol;
MCP callbacks separately use Standard Webhooks.
"""

import hashlib
import hmac
import http.client
import ipaddress
import json
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .webhooks import _DeadlineSocket, _remaining
from .media import MAX_ATTACHMENTS, MediaError, incoming_attachment, same_qq_resource, source_url, QQ_HOSTS

MAX_BODY = 262144


class GatewayRejected(ValueError):
    pass


class AmbiguousSend(RuntimeError):
    """A request may have reached QQ. Never blindly retry it."""


def decode_event(body, headers, secret, *, account_id, peer_id, now):
    """Verify gateway possession separately from the bound sender identity.

    Authenticated message text is still external data, not permission to run tools.
    Only fresh supported messages from one preconfigured owner friend are admitted.
    """
    if not secret or len(body) > MAX_BODY:
        raise GatewayRejected("invalid or oversized gateway request")
    headers = {k.lower(): v for k, v in headers.items()}
    expected = "sha1=" + hmac.new(secret.encode(), body, hashlib.sha1).hexdigest()
    if not hmac.compare_digest(expected, headers.get("x-signature", "")):
        raise GatewayRejected("invalid gateway signature")
    if headers.get("x-self-id") != str(account_id):
        raise GatewayRejected("gateway account mismatch")
    try:
        event = json.loads(body)
        if not isinstance(event, dict):
            raise ValueError()
        if (event.get("post_type"), event.get("message_type"), event.get("sub_type")) != (
            "message", "private", "friend"
        ):
            raise ValueError()
        for field in ("self_id", "user_id", "message_id", "time"):
            if type(event.get(field)) is not int:
                raise ValueError()
        if event["self_id"] != account_id or event["user_id"] != peer_id or peer_id == account_id:
            raise ValueError()
        if not now - 300 <= event["time"] <= now + 60:
            raise ValueError()
        if event.get("sender", {}).get("user_id") != peer_id:
            raise ValueError()
        segments = event["message"]
        if not isinstance(segments, list) or not 1 <= len(segments) <= 100:
            raise ValueError()
        text, attachments = "", []
        for segment in segments:
            if not isinstance(segment, dict):
                raise ValueError()
            if segment.get("type") == "text" and isinstance(segment.get("data", {}).get("text"), str):
                text += segment["data"]["text"]
            else:
                attachments.append(incoming_attachment(segment))
        if (not text.strip() and not attachments) or len(text.encode()) > 64000 or len(attachments) > MAX_ATTACHMENTS:
            raise ValueError()
        return {
            "account_id": str(account_id), "conversation_id": str(peer_id),
            "sender_id": str(peer_id), "message_id": str(event["message_id"]),
            "timestamp": datetime.fromtimestamp(event["time"], timezone.utc).isoformat(),
            "text": text,
            **({"attachments": attachments} if attachments else {}),
        }
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as exc:
        raise GatewayRejected("unsupported, stale, or unbound message") from exc


class LoopbackOneBot:
    """Configured adapter for a colocated gateway; disabled in the fixture CLI.

    Target/account are trusted configuration, never tool arguments. No automatic
    send retry: OneBot send_private_msg has no durable idempotency-key contract.
    """

    def __init__(self, base_url, access_token, *, account_id, peer_id):
        url = urlsplit(base_url)
        try:
            host = ipaddress.ip_address(url.hostname or "")
        except ValueError as exc:
            raise ValueError("gateway must use a literal loopback IP") from exc
        if (url.scheme != "http" or not host.is_loopback or url.username or url.password
                or url.query or url.fragment or url.path not in ("", "/") or not url.port):
            raise ValueError("gateway must be an explicit loopback HTTP origin")
        if (not isinstance(access_token, str) or not access_token or "\r" in access_token
                or "\n" in access_token):
            raise ValueError("gateway token required")
        if type(account_id) is not int or type(peer_id) is not int or min(account_id, peer_id) <= 0 or account_id == peer_id:
            raise ValueError("distinct numeric account and friend IDs required")
        self.host, self.port, self.token = str(host), url.port, access_token
        self.account_id, self.peer_id = account_id, peer_id

    def _call(self, action, params):
        deadline = time.monotonic() + 10
        conn = http.client.HTTPConnection(self.host, self.port, timeout=_remaining(deadline))
        response = None
        try:
            conn.connect()
            conn.sock = _DeadlineSocket(conn.sock, deadline)
            body = json.dumps(params, ensure_ascii=False).encode()
            conn.request("POST", "/" + action, body, {
                "Authorization": "Bearer " + self.token, "Content-Type": "application/json",
            })
            response = conn.getresponse()
            raw = response.read(65537)
            _remaining(deadline)
            if len(raw) > 65536 or response.status != 200:
                raise AmbiguousSend("gateway response unavailable")
            result = json.loads(raw)
            if not isinstance(result, dict) or type(result.get("retcode")) is not int:
                raise AmbiguousSend("malformed gateway response")
            if result.get("status") == "failed" and result["retcode"] != 0:
                raise GatewayRejected("gateway rejected action")
            if result.get("status") != "ok" or result["retcode"] != 0:
                raise AmbiguousSend("unknown gateway outcome")
            return result.get("data")
        except GatewayRejected:
            raise
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise AmbiguousSend("gateway outcome unknown") from exc
        finally:
            if response is not None:
                response.close()
            conn.close()

    def send_text(self, text):
        if not isinstance(text, str) or not text.strip() or len(text.encode()) > 16000:
            raise GatewayRejected("invalid reply text")
        # Avoid sending from an accidentally switched gateway account.
        info = self._call("get_login_info", {})
        if not isinstance(info, dict) or info.get("user_id") != self.account_id:
            raise GatewayRejected("gateway logged-in account mismatch")
        data = self._call("send_private_msg", {
            "user_id": self.peer_id,
            "message": [{"type": "text", "data": {"text": text}}],
            "auto_escape": True,
        })
        if not isinstance(data, dict) or type(data.get("message_id")) is not int:
            raise AmbiguousSend("gateway accepted without a usable message ID")
        return str(data["message_id"])

    def check_account(self):
        # These are preflight reads. Failure here is known to precede any write.
        try:
            info = self._call("get_login_info", {})
            if not isinstance(info, dict) or type(info.get("user_id")) is not int or info["user_id"] != self.account_id:
                raise GatewayRejected("gateway logged-in account mismatch")
        except Exception:
            raise GatewayRejected("gateway account preflight failed") from None

    def read_action(self, action, params):
        if action not in {"get_image", "fetch_face_entity", "search_sys_faces", "fetch_custom_face_detail"}:
            raise GatewayRejected("unsupported read")
        self.check_account()
        try:
            return self._call(action, params)
        except Exception:
            raise GatewayRejected("gateway read unavailable") from None

    def image_url(self, attachment):
        self.check_account()
        original = source_url(attachment["url"], QQ_HOSTS, qq=True)
        if attachment["kind"] == "image" and attachment.get("file"):
            info = self.read_action("get_image", {"file": attachment["file"]})
            if not isinstance(info, dict) or not same_qq_resource(original, info.get("url")):
                raise GatewayRejected("image refresh does not match the admitted resource")
            return source_url(info["url"], QQ_HOSTS, qq=True)
        return original

    def list_custom_faces(self, count):
        data = self.read_action("fetch_custom_face_detail", {"count": count})
        if not isinstance(data, list) or len(data) > count:
            raise GatewayRejected("invalid saved sticker catalog")
        result = []
        for entry in data:
            if (not isinstance(entry, dict) or not isinstance(entry.get("emoji_id"), str)
                    or not 1 <= len(entry["emoji_id"]) <= 200 or not isinstance(entry.get("desc", ""), str)):
                raise GatewayRejected("invalid saved sticker entry")
            result.append({"emoji_id": entry["emoji_id"], "description": entry.get("desc", "")[:200]})
        return result

    def list_faces(self, query):
        data = self.read_action("search_sys_faces", {"query": query})
        if not isinstance(data, dict) or not isinstance(data.get("faces"), list) or len(data["faces"]) > 1000:
            raise GatewayRejected("invalid system face catalog")
        result = []
        for entry in data["faces"]:
            value = entry.get("q_sid") if isinstance(entry, dict) else None
            if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 6:
                result.append({"face_id": int(value), "description": str(entry.get("q_des", ""))[:200]})
        return result[:100]

    def send_operation(self, kind, payload):
        self.check_account()
        if kind == "image":
            action, params = "send_private_msg", {"user_id": self.peer_id, "auto_escape": True,
                "message": [{"type": "image", "data": {"file": "base64://" + payload["data"], "sub_type": 1 if payload["as_sticker"] else 0}}]}
        elif kind == "face":
            face = self.read_action("fetch_face_entity", {"face_id": payload["face_id"]})
            if not isinstance(face, dict) or str(face.get("q_sid")) != str(payload["face_id"]):
                raise GatewayRejected("unknown system face")
            action, params = "send_private_msg", {"user_id": self.peer_id, "auto_escape": True,
                "message": [{"type": "face", "data": {"id": str(payload["face_id"])}}]}
        elif kind == "custom_face":
            if payload["emoji_id"] not in {x["emoji_id"] for x in self.list_custom_faces(48)}:
                raise GatewayRejected("sticker is not in the current bounded collection")
            action, params = "send_custom_face", {"user_id": self.peer_id, "emoji_id": payload["emoji_id"]}
        elif kind == "mface":
            action, params = "send_private_msg", {"user_id": self.peer_id, "auto_escape": True,
                "message": [{"type": "mface", "data": payload}]}
        elif kind == "qzone":
            action, params = "send_qzone_msg", {"content": payload["content"], "ugc_right": payload["ugc_right"],
                "target_uins": payload["target_uins"], "images": ["base64://" + x for x in payload["images"]]}
        else:
            raise GatewayRejected("unsupported write")
        # Recheck after any catalog/network preflight, immediately before writing.
        self.check_account()
        data = self._call(action, params)
        field = "tid" if kind == "qzone" else "message_id"
        value = data.get(field) if isinstance(data, dict) else None
        if type(value) not in (str, int) or not str(value) or len(str(value)) > 200:
            raise AmbiguousSend("gateway accepted without an operation receipt")
        return str(value)
