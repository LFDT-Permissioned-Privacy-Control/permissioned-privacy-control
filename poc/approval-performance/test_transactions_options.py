"""Offline checks for transactions.py helpers; no node, OPS or Docker required."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def load():
    sys.path.insert(0, str(HERE))
    spec = importlib.util.spec_from_file_location("transactions_under_test", HERE / "transactions.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OpsEnvTests(unittest.TestCase):
    def test_pairs_become_overrides(self):
        t = load()
        self.assertEqual(t.parse_ops_env(["OPS_NODE_POLICY_PRINCIPAL_PENDING_LIMIT=18454", "DB_MAX_OPEN_CONNS=30"]),
                         {"OPS_NODE_POLICY_PRINCIPAL_PENDING_LIMIT": "18454", "DB_MAX_OPEN_CONNS": "30"})
        self.assertEqual(t.parse_ops_env(None), {})
        self.assertEqual(t.parse_ops_env(["EMPTY="]), {"EMPTY": ""})

    def test_malformed_pairs_are_refused(self):
        t = load()
        for bad in (["NOEQUALS"], ["=value"], ["lower=1"], ["A B=1"], ["DUP=1", "DUP=2"]):
            with self.assertRaises(ValueError, msg=bad):
                t.parse_ops_env(bad)

    def test_keys_the_stacks_or_flags_own_are_refused(self):
        # The stacks rewrite OPS_APPROVAL_* (and V2 drops them); the request cap
        # has its own flag. Accepting them would record overrides that never applied.
        t = load()
        for owned in (["OPS_APPROVAL_RETAIN_MAX=1"], ["OPS_APPROVAL_TARGETS=x"], ["MAX_CONCURRENT_REQUESTS=10"]):
            with self.assertRaises(ValueError, msg=owned):
                t.parse_ops_env(owned)
        self.assertEqual(t.parse_ops_env(["K=a=b"]), {"K": "a=b"})


class RpcStatusTests(unittest.TestCase):
    def test_counts_are_the_difference_per_status_on_the_rpc_route(self):
        t = load()
        before = "\n".join([
            "# HELP privacyproxy_http_requests_total x",
            'privacyproxy_http_requests_total{method="POST",path="/rpc/:org_id",status="200"} 10',
            'privacyproxy_http_requests_total{method="POST",path="/api/v1/admin/orgs",status="201"} 2',
        ])
        after = "\n".join([
            'privacyproxy_http_requests_total{method="POST",path="/rpc/:org_id",status="200"} 2510',
            'privacyproxy_http_requests_total{method="POST",path="/rpc/:org_id",status="429"} 7',
            'privacyproxy_http_requests_total{method="POST",path="/rpc/:org_id",status="503"} 1e+03',
            'privacyproxy_http_requests_total{method="POST",path="/api/v1/admin/orgs",status="201"} 5',
        ])
        self.assertEqual(t.rpc_status_counts(before, after), {"200": 2500, "429": 7, "503": 1000})

    def test_label_order_unchanged_statuses_and_counter_resets(self):
        t = load()
        before = "\n".join([
            'privacyproxy_http_requests_total{status="200",path="/rpc/:org_id",method="POST"} 100',
            'privacyproxy_http_requests_total{method="POST",path="/rpc/:org_id",status="404"} 3',
        ])
        after = "\n".join([
            # A restarted OPS resets its counters: the after-value is the count.
            'privacyproxy_http_requests_total{status="200",path="/rpc/:org_id",method="POST"} 40',
            'privacyproxy_http_requests_total{method="POST",path="/rpc/:org_id",status="404"} 3',
        ])
        self.assertEqual(t.rpc_status_counts(before, after), {"200": 40})


class ArchiveTests(unittest.TestCase):
    def test_breakdown_counts_files_and_bytes_per_kind(self):
        t = load()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for kind, sizes in {"blocks": [100, 50], "facts": [7], "lists": [3, 3, 3]}.items():
                (root / kind / "00000000").mkdir(parents=True)
                for i, size in enumerate(sizes):
                    (root / kind / "00000000" / str(i)).write_bytes(b"x" * size)
            (root / "pointers").mkdir()
            (root / "pointers" / "facts-head").write_bytes(b"h")
            got = t.archive_breakdown(root)
        self.assertEqual(got["blocks"], {"files": 2, "bytes": 150})
        self.assertEqual(got["facts"], {"files": 1, "bytes": 7})
        self.assertEqual(got["lists"], {"files": 3, "bytes": 9})
        self.assertEqual(got["pointers"], {"files": 1, "bytes": 1})
        self.assertEqual(got["tmp"], {"files": 0, "bytes": 0})

    def test_files_removed_while_listing_are_skipped(self):
        # The node keeps writing and pruning while the report is taken.
        t = load()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "blocks").mkdir()
            (root / "blocks" / "a").write_bytes(b"xy")
            (root / "blocks" / "gone").write_bytes(b"z")
            real_stat = Path.stat

            def vanishing(path, *args, **kwargs):
                # Listed, then pruned before its size is read.
                if path.name == "gone":
                    raise FileNotFoundError(path)
                return real_stat(path, *args, **kwargs)
            Path.stat = vanishing
            try:
                got = t.archive_breakdown(root)
            finally:
                Path.stat = real_stat
        self.assertEqual(got["blocks"], {"files": 1, "bytes": 2})


class GuardedTests(unittest.TestCase):
    def test_a_failing_check_records_its_error_instead_of_raising(self):
        t = load()
        self.assertEqual(t.guarded(lambda: 7), 7)

        def broken():
            raise RuntimeError("relation does not exist")
        self.assertEqual(t.guarded(broken), {"error": "RuntimeError: relation does not exist"})


if __name__ == "__main__":
    unittest.main()
