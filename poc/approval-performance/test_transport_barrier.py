"""Offline crash-barrier checks; no node, Docker, sockets or builds required."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from transport_barrier import NodeTransportBarriers


def request(raw="0x1234", context="first-context"):
    payload = base64.b64encode(json.dumps({"context_id": context}).encode()).decode()
    return {"method": "ops_submitTransaction", "params": [{"payload": payload, "signature": "untouched"}, raw]}


def accepted(tx_hash="0xhash", context="first-context"):
    return {"result": {"transaction_hash": tx_hash, "context_id": context, "status": "accepted", "boot_id": "new-boot"}}


class TransportBarrierTests(unittest.TestCase):
    def setUp(self):
        self.proxy = NodeTransportBarriers("http://127.0.0.1:12345")
        self.addCleanup(self.proxy.close)

    def test_discarding_the_old_sender_allows_a_new_survivor_attempt_only(self):
        barrier = self.proxy.arm({"0x1234": "0xhash"})
        observed, original = self.proxy.enter("a", request())
        self.assertIs(observed, barrier)
        self.assertFalse(original["released"].is_set())
        self.assertEqual(original["record"]["context_id"], "first-context")
        self.assertNotIn("forwarded_at", original["record"])
        with self.assertRaises(RuntimeError):
            barrier.forwarded(original, 200, accepted())
        barrier.drop_held()
        self.assertTrue(original["released"].is_set())
        self.assertTrue(original["drop"])
        with self.assertRaises(RuntimeError):
            barrier.forwarded(original, 200, accepted())
        _, survivor = self.proxy.enter("b", request(context="survivor-context"))
        self.assertTrue(survivor["released"].is_set())
        self.assertFalse(survivor["drop"])
        barrier.forwarded(survivor, 200, accepted(context="survivor-context"))
        records = barrier.snapshot()
        self.assertNotIn("forwarded_at", records[0])
        self.assertTrue(records[1]["accepted"])
        self.assertEqual(records[1]["instance"], "b")

    def test_recovery_gate_forwards_one_then_proves_a_blocked_transport(self):
        barrier = self.proxy.arm({"0x1234": "0xhash", "0x5678": "0xother"}, allow=1)
        _, first = self.proxy.enter("a", request())
        _, held = self.proxy.enter("a", request("0x5678", "other-context"))
        self.assertTrue(first["released"].is_set())
        self.assertFalse(first["record"]["held"])
        self.assertFalse(held["released"].is_set())
        barrier.forwarded(first, 200, accepted())
        self.assertTrue(barrier.wait(lambda rs: any(r.get("accepted") for r in rs) and any(r["held"] for r in rs), .01))
        self.assertEqual(sum(bool(r.get("accepted")) for r in barrier.snapshot()), 1)

    def test_all_instances_are_blocked_until_the_crashed_requests_are_discarded(self):
        barrier = self.proxy.arm({"0x1234": "0xhash"})
        _, a = self.proxy.enter("a", request())
        _, b = self.proxy.enter("b", request(context="other-context"))
        self.assertFalse(a["released"].is_set())
        self.assertFalse(b["released"].is_set())
        barrier.drop_held()
        discarded_at = a["record"]["discarded_at"]
        barrier.drop_held()
        self.assertEqual(a["record"]["discarded_at"], discarded_at)
        self.assertTrue(a["drop"] and b["drop"])

    def test_control_calls_unselected_hashes_and_malformed_requests_are_not_held(self):
        barrier = self.proxy.arm({"0x1234": "0xhash"})
        for value in [None, [], {"method": "ops_policyStatus", "params": []}, request("0xabcd"),
                      {"method": "ops_submitTransaction", "params": []}]:
            with self.subTest(value=value):
                self.assertEqual(self.proxy.enter("a", value), (None, None))
        self.assertEqual(barrier.snapshot(), [])

    def test_no_success_is_recorded_for_an_error_or_mismatched_acknowledgement(self):
        barrier = self.proxy.arm({"0x1234": "0xhash"}, allow=5)
        for status, reply in [(503, accepted()), (200, {"error": {"code": -1}}),
                              (200, accepted(tx_hash="0xwrong")), (200, accepted(context="wrong-context")),
                              (200, None)]:
            _, ticket = self.proxy.enter("a", request())
            barrier.forwarded(ticket, status, reply)
            self.assertFalse(ticket["record"]["accepted"])

    def test_evidence_is_a_snapshot_and_does_not_include_signed_envelopes(self):
        barrier = self.proxy.arm({"0x1234": "0xhash"})
        self.proxy.enter("a", request())
        snapshot = barrier.snapshot()
        snapshot[0]["instance"] = "changed"
        self.assertEqual(barrier.snapshot()[0]["instance"], "a")
        self.assertNotIn("untouched", json.dumps(barrier.snapshot()))

    def test_only_one_active_barrier_and_only_local_nodes_are_allowed(self):
        self.proxy.arm({"0x1234": "0xhash"})
        with self.assertRaises(RuntimeError):
            self.proxy.arm({"0x5678": "0xother"})
        with self.assertRaises(ValueError):
            NodeTransportBarriers("https://remote.example")


class OneShotProbeTests(unittest.TestCase):
    def test_a_lost_response_or_503_never_retries(self):
        spec = importlib.util.spec_from_file_location("live_barrier_under_test", HERE / "live.py")
        live = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(live)
        tx = {"hash": "0xhash", "raw": "0x1234", "signer": "0xsigner", "nonce": 0}
        route = lambda _: ("http://127.0.0.1:12345/rpc/test", "public-test-token")
        for status, payload in [(0, {"transport": "RemoteDisconnected"}), (503, {"error": {"message": "retry"}})]:
            with self.subTest(status=status):
                client = live.Client(workers=1)
                try:
                    with mock.patch.object(client, "attempt", return_value=(status, payload, "1")) as attempt, \
                            mock.patch.object(live.http.client, "HTTPConnection"):
                        record = client.submit_once(tx, route)
                    self.assertEqual(attempt.call_count, 1)
                    self.assertEqual(len(record["attempts"]), 1)
                    self.assertNotIn("accepted_at", record)
                finally:
                    client.close()


if __name__ == "__main__":
    unittest.main()
