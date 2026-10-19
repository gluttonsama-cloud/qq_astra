"""Text-only SnowLuma v2.0.3 OneBot adapter. No login or arbitrary action API.

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
from datetime import datetime, timezone
from urllib.parse import urlsplit

MAX_BODY = 262144


class GatewayRejected(ValueError):
    pass


class AmbiguousSend(RuntimeError):
    """A request may have reached QQ. Never blindly retry it."""


def decode_event(body, headers, secret, *, account_id, peer_id, now):
    """Verify gateway possession separately from the bound sender identity.

    Authenticated message text is still external data, not permission to run tools.
    Only fresh, plain-text messages from one preconfigured friend are admitted.
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
        text = ""
        for segment in segments:
            if segment.get("type") != "text" or not isinstance(segment.get("data", {}).get("text"), str):
                raise ValueError()
            text += segment["data"]["text"]
        if not text.strip() or len(text.encode()) > 64000:
            raise ValueError()
        return {
            "account_id": str(account_id), "conversation_id": str(peer_id),
            "sender_id": str(peer_id), "message_id": str(event["message_id"]),
            "timestamp": datetime.fromtimestamp(event["time"], timezone.utc).isoformat(),
            "text": text,
        }
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as exc:
        raise GatewayRejected("unsupported, stale, or unbound message") from exc


class LoopbackOneBot:
    """Explicitly injected adapter for a colocated gateway; not enabled by the CLI.

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
        conn = http.client.HTTPConnection(self.host, self.port, timeout=10)
        try:
            body = json.dumps(params, ensure_ascii=False).encode()
            conn.request("POST", "/" + action, body, {
                "Authorization": "Bearer " + self.token, "Content-Type": "application/json",
            })
            response = conn.getresponse()
            raw = response.read(65537)
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
