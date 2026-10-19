"""Offline fixtures only. No network, QQ login, MCP server, or dot invocation."""

import hashlib
import json
from datetime import datetime

EVENT_NAME = "qq.message.created"
ALLOWED = ("fixture-bot", "fixture-private-chat", "fixture-owner")

# A proposed bridge event catalog, using the official MCP Events response shape.
# These are our field names, not a verified SnowLuma/QQ wire format.
EVENTS_LIST_RESPONSE = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "events": [{
            "name": EVENT_NAME,
            "description": "A message from the linked owner in an allowed private QQ chat.",
            "delivery": ["webhook"],
            "inputSchema": {
                "type": "object",
                "properties": {
                    key: {"type": "string"}
                    for key in ("account_id", "conversation_id", "sender_id")
                },
                "required": ["account_id", "conversation_id", "sender_id"],
                "additionalProperties": False,
            },
            "payloadSchema": {
                "type": "object",
                "properties": {
                    key: {"type": "string"}
                    for key in ("account_id", "conversation_id", "sender_id", "message_id", "text")
                },
                "required": ["account_id", "conversation_id", "sender_id", "message_id", "text"],
                "additionalProperties": False,
            },
        }],
    },
}


def fixture(**overrides):
    record = {
        "account_id": ALLOWED[0],
        "conversation_id": ALLOWED[1],
        "sender_id": ALLOWED[2],
        "message_id": "fixture-message-001",
        "timestamp": "2026-10-19T15:00:00Z",
        "text": "这是一条虚构的 QQ 测试消息。",
    }
    return {**record, **overrides}


class OfflineBridge:
    """In-memory demonstration; caller identity is simulated, never authenticated."""

    def __init__(self):
        self.events = {}
        self.reply_calls = []
        self.replies = {}

    def ingest(self, record):
        expected = set(fixture())
        if set(record) != expected or any(not isinstance(v, str) or not v for v in record.values()):
            return {"status": "rejected", "reason": "invalid_record"}
        identity = tuple(record[key] for key in ("account_id", "conversation_id", "sender_id"))
        if identity != ALLOWED:
            return {"status": "rejected", "reason": "not_allowlisted"}
        try:
            if datetime.fromisoformat(record["timestamp"]).tzinfo is None:
                raise ValueError("Timezone required")
        except ValueError:
            return {"status": "rejected", "reason": "invalid_timestamp"}
        # Hashing is for a stable identifier, not authentication or a signing secret.
        identity_bytes = json.dumps([*identity, record["message_id"]]).encode()
        event_id = "qq_" + hashlib.sha256(identity_bytes).hexdigest()
        if event_id in self.events:
            return {"status": "duplicate", "eventId": event_id}
        event = {
            "eventId": event_id,
            "name": EVENT_NAME,
            "timestamp": record["timestamp"],
            "data": {key: value for key, value in record.items() if key != "timestamp"},
            "cursor": None,
        }
        if len(json.dumps(event, ensure_ascii=False).encode()) > 256 * 1024:
            return {"status": "rejected", "reason": "payload_too_large"}
        self.events[event_id] = event
        return {"status": "accepted_offline", "event": event}

    def call_reply_tool(self, *, event_id, conversation_id, text):
        """A local mock tool. Only records a reply; it cannot send anything."""
        event = self.events.get(event_id)
        if event is None or event["data"]["conversation_id"] != conversation_id:
            raise ValueError("Unknown event or reply target mismatch")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("Reply must be nonempty text")
        arguments = {
            "event_id": event_id,
            "account_id": event["data"]["account_id"],
            "conversation_id": conversation_id,
            "text": text,
            "idempotency_key": event_id + ":reply",
        }
        if event_id in self.replies:
            if self.replies[event_id] != arguments:
                raise ValueError("Conflicting reply for an already processed event")
            return {"status": "already_recorded_offline", "sent": False}
        self.replies[event_id] = arguments
        self.reply_calls.append({"tool": "qq_reply_mock", "arguments": arguments})
        return {"status": "recorded_offline", "sent": False}


def demo():
    bridge = OfflineBridge()
    source = fixture()
    result = bridge.ingest(source)
    event = result["event"]
    reply_args = {
        "event_id": event["eventId"],
        "conversation_id": source["conversation_id"],
        "text": "模拟回复：桥接格式验证成功。",
    }
    reply = bridge.call_reply_tool(**reply_args)
    return {
        "mode": "offline_simulation_only",
        "synthetic_input": source,
        "event": event,
        "duplicate_input": bridge.ingest(source),
        "unknown_sender": bridge.ingest(fixture(sender_id="fixture-stranger")),
        "other_chat": bridge.ingest(fixture(conversation_id="fixture-other-chat")),
        "bot_echo": bridge.ingest(fixture(sender_id="fixture-bot")),
        "reply_result": reply,
        "recorded_reply_tool_calls": bridge.reply_calls,
        "recorded_reply_tool_call_count": len(bridge.reply_calls),
        "verified_live": {
            "snowluma_adapter": False,
            "qq_login": False,
            "oauth": False,
            "events_subscription": False,
            "callback_verification": False,
            "same_dot_delivery": False,
            "qq_reply_sent": False,
        },
    }


if __name__ == "__main__":
    print(json.dumps(demo(), ensure_ascii=False, indent=2))
