import unittest

from bridge_sim import EVENTS_LIST_RESPONSE, OfflineBridge, demo, fixture


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.bridge = OfflineBridge()

    def test_event_envelope_and_declared_payload(self):
        event = self.bridge.ingest(fixture())["event"]
        self.assertEqual(set(event), {"eventId", "name", "timestamp", "data", "cursor"})
        definition = EVENTS_LIST_RESPONSE["result"]["events"][0]
        self.assertEqual(event["name"], definition["name"])
        self.assertEqual(set(event["data"]), set(definition["payloadSchema"]["required"]))
        self.assertTrue(all(isinstance(value, str) for value in event["data"].values()))
        self.assertIsNone(event["cursor"])

    def test_duplicate_message_creates_one_event(self):
        self.bridge.ingest(fixture())
        self.assertEqual(self.bridge.ingest(fixture())["status"], "duplicate")
        self.assertEqual(len(self.bridge.events), 1)

    def test_reject_unknown_sender(self):
        self.assertEqual(self.bridge.ingest(fixture(sender_id="stranger"))["status"], "rejected")

    def test_reject_other_chat(self):
        self.assertEqual(self.bridge.ingest(fixture(conversation_id="other-chat"))["status"], "rejected")

    def test_reject_other_account(self):
        self.assertEqual(self.bridge.ingest(fixture(account_id="other-account"))["status"], "rejected")

    def test_reject_bot_echo(self):
        self.assertEqual(self.bridge.ingest(fixture(sender_id="fixture-bot"))["status"], "rejected")

    def test_reject_missing_or_bad_fields(self):
        record = fixture()
        del record["message_id"]
        self.assertEqual(self.bridge.ingest(record)["reason"], "invalid_record")
        self.assertEqual(self.bridge.ingest(fixture(text=None))["reason"], "invalid_record")

    def test_reject_naive_or_invalid_timestamp(self):
        for timestamp in ("2026-10-19T15:00:00", "bad"):
            with self.subTest(timestamp=timestamp):
                self.assertEqual(self.bridge.ingest(fixture(timestamp=timestamp))["reason"], "invalid_timestamp")

    def test_reject_oversized_event(self):
        self.assertEqual(self.bridge.ingest(fixture(text="x" * (256 * 1024)))["reason"], "payload_too_large")

    def test_unknown_event_cannot_reply(self):
        with self.assertRaises(ValueError):
            self.bridge.call_reply_tool(event_id="unknown", conversation_id="fixture-private-chat", text="test")

    def test_reply_cannot_redirect(self):
        event = self.bridge.ingest(fixture())["event"]
        with self.assertRaises(ValueError):
            self.bridge.call_reply_tool(event_id=event["eventId"], conversation_id="other-chat", text="test")

    def test_conflicting_reply_rejected(self):
        event = self.bridge.ingest(fixture())["event"]
        args = {"event_id": event["eventId"], "conversation_id": "fixture-private-chat", "text": "first"}
        self.bridge.call_reply_tool(**args)
        with self.assertRaises(ValueError):
            self.bridge.call_reply_tool(**{**args, "text": "second"})
        self.assertEqual(len(self.bridge.reply_calls), 1)

    def test_identical_reply_retry_is_idempotent(self):
        event = self.bridge.ingest(fixture())["event"]
        args = {"event_id": event["eventId"], "conversation_id": "fixture-private-chat", "text": "same"}
        self.bridge.call_reply_tool(**args)
        result = self.bridge.call_reply_tool(**args)
        self.assertEqual(result["status"], "already_recorded_offline")
        self.assertEqual(len(self.bridge.reply_calls), 1)

    def test_demo_records_exactly_one_reply_and_no_live_success(self):
        result = demo()
        self.assertEqual(result["recorded_reply_tool_call_count"], 1)
        self.assertFalse(result["reply_result"]["sent"])
        self.assertFalse(any(result["verified_live"].values()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
