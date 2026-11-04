#!/usr/bin/env python3
"""Live acceptance scenarios for OPS V2 against the real guarded node (plan
RD-1410 §8, L1 and L3-L13; L2 is node/reth/scripts/crash.py).

Each run starts one fresh V2 stack (v2stack.V2Stack: PostgreSQL, Redis, the
guarded ops-reth without --dev on fresh data and policy state directories, OPS
in Reth policy mode with an activated baseline execution policy), adds
principals whose wallets are public development keys (node/reth/scripts/
load-sign; never real assets), drives blocks through the Engine API and checks
the outcome against the chain, the node's private API and the execution-tracking
database. A client sends every transaction once and resends the same raw
transaction only after a 429/503 or a lost connection, as a wallet does; the
scenarios that require "no client action" check that no resend happened.

Writes <output>/result.json: one entry per check with pass/fail and evidence,
plus the timeline. Not a throughput measurement.

    python3 poc/approval-performance/live.py --scenario kill-under-load --output .tmp/p7/live/kill
"""
import argparse
import collections
import concurrent.futures
import contextlib
import http.client
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import urllib.parse

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TARGET = "0x1f98431c8ad98523631ae4a59f267346ea31f984"
# Init code returning a 10-byte runtime that returns 42 (a contract creation).
INIT_CODE = "0x600a600c600039600a6000f3602a60005260206000f3"
TX_GAS = 300_000  # load-sign's gas limit


def now():
    return time.time()


def percentile(values, q):
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, int(round((len(values) - 1) * q)))]


class Result:
    """Checks and a timeline, written as the run goes (a crash keeps both)."""

    def __init__(self, path, scenario):
        self.path, self.data = path, {"scenario": scenario, "started": now(), "checks": [], "timeline": [], "evidence": {}}
        self.lock = threading.Lock()

    def event(self, what, **details):
        with self.lock:
            self.data["timeline"].append({"at": round(now(), 3), "event": what, **details})
        print(f"{time.strftime('%H:%M:%S')} {what} {json.dumps(details)[:300] if details else ''}", flush=True)
        self.save()

    def check(self, name, passed, **evidence):
        with self.lock:
            self.data["checks"].append({"check": name, "pass": bool(passed), **evidence})
        print(f"{'PASS' if passed else 'FAIL'} {name} {json.dumps(evidence)[:400]}", flush=True)
        self.save()

    def evidence(self, key, value):
        with self.lock:
            self.data["evidence"][key] = value
        self.save()

    def save(self):
        self.data["passed"] = all(c["pass"] for c in self.data["checks"]) if self.data["checks"] else None
        self.path.write_text(json.dumps(self.data, indent=1, default=str) + "\n")


def sign(signers, per_signer, target=TARGET):
    """Pre-signed EIP-155 transfers: signer i has nonces 0..per_signer-1."""
    out = json.loads(subprocess.check_output(["go", "run", "./node/reth/scripts/load-sign", "-count", str(signers * per_signer),
                                              "-senders", str(signers), "-target", target], cwd=ROOT))
    keys = {address.lower(): "%064x" % (i + 1) for i, address in enumerate(out["senders"])}
    by_signer = collections.defaultdict(list)
    for tx in out["transactions"][:signers * per_signer]:
        tx = dict(tx, hash=tx["hash"].lower(), signer=tx["signer"].lower())
        by_signer[tx["signer"]].append(tx)
    return keys, {s: sorted(txs, key=lambda t: t["nonce"]) for s, txs in by_signer.items()}


def budget_excess(samples, budget, burst=2.0, min_gap=5.0, column=4):
    """Worst excess of a cumulative renewal counter over the keeper's token
    bucket (budget per second, up to `burst` seconds banked) across sample
    pairs at least min_gap apart: renewals(a, b) − budget × (Δt + burst).
    ≤ 0 means within budget."""
    worst = float("-inf")
    for i, a in enumerate(samples):
        for b in samples[i + 1:]:
            if b[0] - a[0] >= min_gap:
                worst = max(worst, (b[column] - a[column]) - budget * (b[0] - a[0] + burst))
    return worst if worst != float("-inf") else 0.0


def interleave(groups):
    """Round-robin over signers, so each signer's nonces stay in order."""
    out, queues = [], [list(g) for g in groups]
    while any(queues):
        for q in queues:
            if q:
                out.append(q.pop(0))
    return out


def is_included(receipt):
    """A successful canonical receipt (a lookup error is not one)."""
    return bool(receipt) and receipt.get("status") == "0x1"


def is_absent(receipt):
    """No receipt at all (a lookup error is not absence)."""
    return receipt is None


class Principal:
    def __init__(self, did, uid, token, signers):
        self.did, self.uid, self.token, self.signers = did, uid, token, signers


class Driver:
    """Engine API block driver like the gate-1 one (1 s cadence, 0.8 s build
    window), with a finality lag in blocks, pause/resume, recovery from node
    restarts (it re-reads the head) and a one-block reorg."""

    def __init__(self, node, h, result, finality_lag=0, interval=1.0, window=0.8):
        self.node, self.h, self.result = node, h, result
        self.lag, self.interval, self.window = finality_lag, interval, window
        self.blocks, self.errors = [], []
        self.lock = threading.Lock()
        self.running, self.stopping = threading.Event(), threading.Event()
        self.running.set()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def finalized_hash(self, head_number):
        number = max(0, head_number - self.lag)
        return self.node.rpc("eth_getBlockByNumber", hex(number), False)["hash"]

    def build(self, parent, build_window):
        n = self.node
        fin = self.finalized_hash(int(parent["number"], 16))
        state = {"headBlockHash": parent["hash"], "safeBlockHash": fin, "finalizedBlockHash": fin}
        attrs = {"timestamp": hex(max(int(parent["timestamp"], 16) + 1, int(now()))), "prevRandao": self.h.ZERO,
                 "suggestedFeeRecipient": self.h.ADMIN, "withdrawals": []}
        answer = n.engine("engine_forkchoiceUpdatedV2", state, attrs)
        if answer["payloadStatus"]["status"] != "VALID" or not answer.get("payloadId"):
            raise RuntimeError(f"forkchoice with attributes: {answer}")
        if build_window:
            self.stopping.wait(build_window)
        payload = n.engine("engine_getPayloadV2", answer["payloadId"])["executionPayload"]
        answer = n.engine("engine_newPayloadV2", payload)
        if answer["status"] != "VALID":
            raise RuntimeError(f"newPayload: {answer}")
        number = int(payload["blockNumber"], 16)
        fin = self.finalized_hash(number) if self.lag else payload["blockHash"]
        answer = n.engine("engine_forkchoiceUpdatedV2", {"headBlockHash": payload["blockHash"], "safeBlockHash": fin, "finalizedBlockHash": fin}, None)
        if answer["payloadStatus"]["status"] != "VALID":
            raise RuntimeError(f"forkchoice: {answer}")
        n.head = n.rpc("eth_getBlockByNumber", payload["blockNumber"], False)
        block = {"at": round(now(), 3), "number": number, "hash": payload["blockHash"], "parent": payload["parentHash"],
                 "transactions": [t.lower() for t in n.head["transactions"]], "gas_used": int(payload["gasUsed"], 16)}
        self.blocks.append(block)
        return block

    def run(self):
        while not self.stopping.is_set():
            if not self.running.is_set():
                self.stopping.wait(.05)
                continue
            started = time.monotonic()
            with self.lock:
                if not self.running.is_set():
                    continue  # paused while waiting for the lock
                try:
                    self.build(self.node.head, self.window)
                except Exception as error:  # node restarting, facts stale, ...
                    self.errors.append({"at": round(now(), 3), "error": str(error)[:300]})
                    try:
                        self.node.head = self.node.rpc("eth_getBlockByNumber", "latest", False)
                    except Exception:
                        pass
                    self.stopping.wait(.5)
                    continue
            self.stopping.wait(max(0, self.interval - (time.monotonic() - started)))

    def pause(self):
        with self.lock:
            self.running.clear()

    def resume(self):
        with self.lock:
            self.node.head = self.node.rpc("eth_getBlockByNumber", "latest", False)
            self.running.set()

    def reorg(self):
        """Replace the head block by a rival built at once on its parent
        (normally empty: the pool still lacks the replaced block's transactions)."""
        with self.lock:
            replaced = self.node.head
            parent = self.node.rpc("eth_getBlockByNumber", hex(int(replaced["number"], 16) - 1), False)
            rival = self.build(parent, 0)
            rival["reorg_of"] = replaced["hash"]
            return replaced, rival

    def close(self):
        self.stopping.set()
        self.thread.join(timeout=40)


class Client:
    """A wallet-like sender: one request per transaction; the same raw
    transaction again only after 429/503 (Retry-After) or a lost connection."""

    def __init__(self, workers=48):
        self.local = threading.local()
        self.pool = concurrent.futures.ThreadPoolExecutor(workers)
        self.records, self.lock = {}, threading.Lock()

    def post(self, url, token, body):
        conns = self.local.__dict__.setdefault("conns", {})
        target = urllib.parse.urlparse(url)
        conn = conns.get(target.netloc)
        if conn is not None:
            # A kept-alive connection the server closed while idle fails at
            # once on reuse; any HTTP client reconnects and sends again (the
            # same raw transaction is idempotent).
            status, payload, retry_after = self.attempt(conn, target, token, body, conns)
            if status or payload.get("transport") not in ("RemoteDisconnected", "ConnectionResetError", "BrokenPipeError"):
                return status, payload, retry_after
        conn = conns[target.netloc] = http.client.HTTPConnection(target.netloc, timeout=60)
        return self.attempt(conn, target, token, body, conns)

    def attempt(self, conn, target, token, body, conns):
        try:
            conn.request("POST", target.path, body, {"Content-Type": "application/json", "Authorization": "Bearer " + token})
            response = conn.getresponse()
            data = response.read()
            try:
                payload = json.loads(data)
            except ValueError:
                payload = {"body": data[:200].decode(errors="replace")}
            return response.status, payload, response.getheader("Retry-After")
        except Exception as error:
            conn.close()
            conns.pop(target.netloc, None)
            return 0, {"transport": type(error).__name__}, None

    def submit(self, tx, route, deadline):
        """route(tx) -> (rpc url, token). Returns the record."""
        with self.lock:
            record = self.records.setdefault(tx["hash"], {"hash": tx["hash"], "signer": tx["signer"], "nonce": tx["nonce"], "attempts": []})
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": [tx["raw"]]})
        while True:
            url, token = route(tx)
            started = now()
            status, payload, retry_after = self.post(url, token, body)
            ended = now()
            error = payload.get("error") if isinstance(payload, dict) else None
            ok = status == 200 and not error and isinstance(payload, dict) and str(payload.get("result", "")).lower() == tx["hash"]
            record["attempts"].append([round(started, 3), round(ended - started, 4), status,
                                       (error or {}).get("code") if isinstance(error, dict) else None,
                                       ((error or {}).get("message") if isinstance(error, dict) else None) or payload.get("transport")])
            if ok:
                record["accepted_at"] = round(ended, 3)
                return record
            if status not in (0, 429, 503) or now() > deadline:
                record["refused"] = status
                return record
            time.sleep(min(5.0, float(retry_after or 1)))

    def submit_once(self, tx, route):
        """One wire attempt for a saved-intent crash probe; never reconnect/retry."""
        url, token = route(tx)
        target = urllib.parse.urlparse(url)
        conn = http.client.HTTPConnection(target.netloc, timeout=60)
        started = now()
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": [tx["raw"]]})
        try:
            status, payload, _ = self.attempt(conn, target, token, body, {})
        finally:
            conn.close()
        payload = payload if isinstance(payload, dict) else {"transport": "invalid_response"}
        record = {"hash": tx["hash"], "signer": tx["signer"], "nonce": tx["nonce"], "one_shot": True,
                  "attempts": [[round(started, 3), round(now() - started, 4), status, None, payload.get("transport")]]}
        if status == 200 and not payload.get("error") and payload.get("result") == tx["hash"]:
            record["accepted_at"] = now()
        with self.lock:
            self.records[tx["hash"]] = record
        return record

    def open_loop(self, txs, rate, route, deadline):
        """Schedules txs at a fixed rate; returns futures. Each record keeps
        its scheduled time, so latency can include any wait for a worker."""
        start, futures = now(), []
        for i, tx in enumerate(txs):
            scheduled = start + i / rate
            delay = scheduled - now()
            if delay > 0:
                time.sleep(delay)
            with self.lock:
                self.records.setdefault(tx["hash"], {"hash": tx["hash"], "signer": tx["signer"], "nonce": tx["nonce"], "attempts": []})["scheduled"] = round(scheduled, 4)
            futures.append(self.pool.submit(self.submit, tx, route, deadline))
        return futures

    def close(self):
        self.pool.shutdown(wait=True)


class Live:
    """One stack plus helpers shared by the scenarios."""

    def __init__(self, args, result, ops_env=None, gas_limit=200_000_000, finality_lag=0, signers=8, per_signer=200, principals=1, reserve=0,
                 transport_barriers=False):
        self.args, self.result = args, result
        os.environ.update(OPS_EVIDENCE_DIR=str(args.output), OPS_POC_KEEPALIVE="1", OPS_POC_GAS_LIMIT=str(gas_limit))
        os.environ.setdefault("OPS_RETH_BINARY", str(ROOT / ".tmp/approval-target/release/ops-reth-approvals"))
        sys.path.insert(0, str(ROOT / "poc/reth-signed-approvals"))
        sys.path.insert(0, str(HERE))
        import gasstorm_compare as g
        import harness as h
        import v2stack
        from demo import request
        self.g, self.h, self.v2stack, self.request = g, h, v2stack, request
        g.prepare()
        self.keys, self.txs = sign(signers, per_signer)
        genesis = json.loads((h.EVIDENCE / "genesis.json").read_text())
        genesis["gasLimit"] = hex(gas_limit)
        for address in self.keys:
            genesis["alloc"][address] = {"balance": hex(10**24)}
        (h.EVIDENCE / "genesis.json").write_text(json.dumps(genesis) + "\n")
        self.stack = v2stack.V2Stack("live-" + args.scenario, ops_env=ops_env or {}, transport_barriers=transport_barriers)
        try:
            self.setup(args, result, ops_env, gas_limit, finality_lag, principals, reserve)
        except BaseException:
            # Never leave the node, OPS or the containers behind.
            self.stack.close()
            raise

    def setup(self, args, result, ops_env, gas_limit, finality_lag, principals, reserve):
        h = self.h
        result.evidence("stack", {"ops": self.stack.url, "node_rpc": self.stack.node.rpc_url, "directory": str(self.stack.directory),
                                  "node_directory": str(self.stack.node.directory), "ops_env_overrides": ops_env or {},
                                  "gas_limit": gas_limit, "finality_lag_blocks": finality_lag,
                                  "ops_binary": str(self.stack.ops_binary), "node_binary": str(self.v2stack.V2_BINARY)})
        self.client = Client()
        self.principals, self.owner = [], {}
        signer_list = sorted(self.txs, key=lambda s: int(self.keys[s], 16))
        # The last `reserve` signers stay unlinked for principals a scenario adds.
        self.reserved = signer_list[len(signer_list) - reserve:] if reserve else []
        signer_list = signer_list[:len(signer_list) - reserve] if reserve else signer_list
        share = len(signer_list) // principals
        for p in range(principals):
            mine = signer_list[p * share:(p + 1) * share] if p < principals - 1 else signer_list[p * share:]
            self.add_principal(f"did:test:live-{args.scenario}-p{p}", mine)
        self.wait_facts_current()
        self.driver = Driver(self.stack.node, h, result, finality_lag=finality_lag)
        result.event("stack ready", principals=[p.uid for p in self.principals])

    # --- OPS and node access -------------------------------------------------

    def add_principal(self, did, signers):
        s, request = self.stack, self.request
        s.login(did)
        users = s.admin("GET", "/users?search=" + urllib.parse.quote(did))
        uid = next(u["id"] for u in users["data"] if u["external_id"] == did)
        s.admin("PUT", "/users/" + uid, {"kyc": True})
        for membership in s.admin("GET", f"/users/{uid}/memberships"):
            s.admin("DELETE", f"/users/{uid}/memberships/{membership['membership']['id']}")
        s.admin("POST", f"/users/{uid}/memberships", {"group_id": s.group})
        token = s.login(did)
        for address in signers:
            challenge = request(s.url + "/api/v1/eth/link/challenge", "POST", {}, token)
            signature = self.h.command(["cast", "wallet", "sign", "--private-key", self.keys[address], challenge["message"]])
            request(s.url + "/api/v1/eth/link/verify", "POST", {"nonce": challenge["nonce"], "address": address, "signature": signature}, token)
        principal = Principal(did, uid, token, signers)
        self.principals.append(principal)
        for address in signers:
            self.owner[address] = principal
        return principal

    def route(self, url=None):
        base = url or self.stack.url
        return lambda tx: (base + "/rpc/" + self.stack.org, self.owner[tx["signer"]].token)

    def private(self, method, params, timeout=30):
        target = urllib.parse.urlparse(self.stack.node.private_url)
        conn = http.client.HTTPConnection(target.netloc, timeout=timeout)
        try:
            conn.request("POST", "/", json.dumps({"jsonrpc": "2.0", "id": "live", "method": method, "params": params}),
                         {"Content-Type": "application/json", "Authorization": "Bearer " + self.stack.node_token})
            return json.loads(conn.getresponse().read())
        finally:
            conn.close()

    def node_version(self):
        reply = self.private("ops_policyStatus", [], timeout=5)
        return reply["result"]["version"], reply["result"]["ready"], reply["result"].get("reason"), reply["result"].get("boot_id")

    def boot(self):
        try:
            return self.node_version()[3]
        except Exception:
            return None

    def load(self, txs, rate, route, deadline):
        """Runs an open loop in the background; join() returns the records."""
        futures, done = [], threading.Event()

        def run():
            try:
                futures.extend(self.client.open_loop(txs, rate, route, deadline))
            finally:
                done.set()
        threading.Thread(target=run, daemon=True).start()

        class Load:
            def join(_):
                done.wait()
                return [f.result() for f in futures]
        return Load()

    def db_version(self):
        return int(self.stack.psql("SELECT version FROM node_policy_clock"))

    def wait_facts_current(self, limit=60):
        deadline = now() + limit
        while now() < deadline:
            try:
                version, ready, _, _ = self.node_version()
                if ready and version >= self.db_version():
                    return version
            except Exception:
                pass
            time.sleep(.2)
        raise RuntimeError("node facts never caught up with the database")

    def rows(self, sql, database="exec"):
        """Rows of a query on the tracking ("exec"), main ("ops_approvals_demo")
        or audit ("ops_approvals_demo_audit") database."""
        text = self.stack.psql_exec(sql) if database == "exec" else self.stack.psql(sql, database)
        return [line.split("|") for line in text.splitlines() if line]

    def tracking(self):
        """hash -> (where, state, reason, block): binding (in flight) or final."""
        out = {}
        for hx, state, reason, block in self.rows("SELECT encode(tx_hash,'hex'), state, reason, coalesce(block_number,-1) FROM node_tx_binding"):
            out["0x" + hx] = ("binding", int(state), int(reason), int(block))
        for hx, state, reason, block in self.rows("SELECT encode(tx_hash,'hex'), state, reason, coalesce(block_number,-1) FROM node_tx_status"):
            out["0x" + hx] = ("final", int(state), int(reason), int(block))
        return out

    def final_rows_per_hash(self):
        return {"0x" + hx: int(n) for hx, n in self.rows("SELECT encode(tx_hash,'hex'), count(*) FROM node_tx_status GROUP BY 1")}

    def history(self):
        """hash -> [(generation, actor, reason)] (system rows: renewals, recoveries, stops)."""
        out = collections.defaultdict(list)
        for hx, gen, actor, reason in self.rows("SELECT encode(tx_hash,'hex'), generation, actor, reason FROM node_tx_identities ORDER BY seq"):
            out["0x" + hx].append((int(gen), int(actor), int(reason)))
        return out

    def db_now(self):
        """The database clock (epoch seconds): tracking timestamps use it."""
        return float(self.stack.psql_exec("SELECT extract(epoch FROM clock_timestamp())"))

    def system_rows_between(self, start, end, reasons):
        """System history rows (actor 2) with these reasons written in [start, end) (database clock)."""
        reasons_sql = ",".join(str(int(r)) for r in reasons)
        return int(self.stack.psql_exec(f"SELECT count(*) FROM node_tx_identities WHERE actor = 2 AND reason IN ({reasons_sql}) "
                                        f"AND created_at >= to_timestamp({start}) AND created_at < to_timestamp({end})"))

    def receipts(self, hashes):
        """hash -> receipt summary, None (no receipt) or {"error"} after three
        failed lookups (neither included nor absent: see is_included / is_absent)."""
        def one(tx_hash):
            for attempt in range(3):
                try:
                    r = self.stack.node.rpc("eth_getTransactionReceipt", tx_hash)
                    break
                except Exception as error:
                    if attempt == 2:
                        return tx_hash, {"error": str(error)}
                    time.sleep(.5)
            return tx_hash, None if r is None else {"block": int(r["blockNumber"], 16), "hash": r["blockHash"], "status": r["status"]}
        with concurrent.futures.ThreadPoolExecutor(16) as pool:
            return dict(pool.map(one, list(hashes)))

    def identities_of_included(self, included):
        """Every included transaction executed under an identity of the
        principal that owns its signer (node manifest, batched status)."""
        bad, unanswered = [], list(included)
        for _ in range(20):
            retry = []
            for i in range(0, len(unanswered), 256):
                chunk = unanswered[i:i + 256]
                reply = self.private("ops_transactionStatuses", [[c for c, _ in chunk]])
                if "error" in reply:
                    raise RuntimeError(reply["error"])
                for (tx_hash, signer), entry in zip(chunk, reply["result"]["statuses"]):
                    if entry is None:
                        retry.append((tx_hash, signer))
                    elif entry["principal_id"] != self.owner[signer].uid or entry["execution"]["status"] not in ("included", "reverted"):
                        bad.append({"hash": tx_hash, "principal": entry["principal_id"], "status": entry["execution"]["status"]})
            if not retry:
                return bad, []
            unanswered = retry
            time.sleep(1)
        return bad, unanswered

    def wait_until(self, predicate, limit, step=1.0):
        deadline = now() + limit
        while now() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(step)
        return predicate()

    def all_settled(self, hashes, limit):
        """Wait until every hash has a final tracking row; returns the tracking map."""
        hashes = set(hashes)

        def settled():
            t = self.tracking()
            return t if all(t.get(x, ("", 0))[0] == "final" for x in hashes) else None
        return self.wait_until(settled, limit, 2.0) or self.tracking()

    def outcome_checks(self, sent, label, settle=120, expect_all_included=True):
        """Common end checks over the transactions the client sent."""
        accepted = [r for r in sent if r.get("accepted_at")]
        refused = [r for r in sent if not r.get("accepted_at")]
        resent = [r for r in accepted if len(r["attempts"]) > 1]
        self.result.evidence(label + "_client", {"sent": len(sent), "accepted": len(accepted), "refused": len(refused),
                                                  "accepted_after_resend": len(resent),
                                                  "refusals_by_status": collections.Counter(str(r.get("refused")) for r in refused),
                                                  "attempt_statuses": collections.Counter(str(a[2]) for r in sent for a in r["attempts"])})
        tracking = self.all_settled([r["hash"] for r in accepted], settle)
        receipts = self.receipts([r["hash"] for r in accepted])
        included = [r for r in accepted if is_included(receipts.get(r["hash"]))]
        states = collections.Counter(f"{v[0]}:{v[1]}:{v[2]}" for k, v in tracking.items() if k in {r["hash"] for r in accepted})
        not_final = [r["hash"] for r in accepted if tracking.get(r["hash"], ("",))[0] != "final"]
        on_chain = {r["hash"] for r in included}
        final_but_not_on_chain = [r["hash"] for r in accepted if tracking.get(r["hash"], ("", 0))[:2] == ("final", 10) and r["hash"] not in on_chain]
        self.result.evidence(label + "_tracking_states", dict(states))
        if not_final:
            # Which state and block the unsettled rows are in, and whether the
            # node's chain holds them there (a block lost in a crash does not).
            head = int(self.stack.node.rpc("eth_blockNumber"), 16)
            sample = []
            for x in not_final[:15]:
                where, state, reason, block = tracking.get(x, ("?", 0, 0, -1))
                in_block = None
                if 0 <= block <= head:
                    in_block = x in [t.lower() for t in self.stack.node.rpc("eth_getBlockByNumber", hex(block), False)["transactions"]]
                sample.append({"hash": x, "where": where, "state": state, "reason": reason, "block": block, "in_that_block_now": in_block})
            self.result.evidence(label + "_unsettled_sample", {"node_head": head, "rows": sample})
        if expect_all_included:
            self.result.check(f"{label}: every accepted transaction is included on chain", len(included) == len(accepted),
                              accepted=len(accepted), included=len(included),
                              missing=[r["hash"] for r in accepted if r["hash"] not in on_chain][:20])
        self.result.check(f"{label}: every accepted transaction reached a defined final state in OPS", not not_final,
                          not_final=len(not_final), sample=not_final[:10])
        self.result.check(f"{label}: OPS final 'included' agrees with the chain", not final_but_not_on_chain, mismatches=final_but_not_on_chain[:10])
        bad, unanswered = self.identities_of_included([(r["hash"], r["signer"]) for r in included])
        self.result.check(f"{label}: every included transaction executed under its own principal's identity (node manifests)",
                          not bad and not unanswered, checked=len(included), wrong=bad[:10], unanswered=len(unanswered))
        duplicates = {k: v for k, v in self.final_rows_per_hash().items() if v != 1}
        self.result.check(f"{label}: each transaction finalized once in OPS", not duplicates, duplicates=list(duplicates.items())[:10])
        return accepted, included, tracking

    def renewals(self, hashes=None):
        counts = collections.Counter()
        for hx, rows in self.history().items():
            if hashes is not None and hx not in hashes:
                continue
            for _, actor, reason in rows:
                counts[f"actor{actor}:reason{reason}"] += 1
        return dict(counts)

    def ops_log_lines(self, needle, path=None):
        path = path or (self.stack.directory / "ops.log")
        return [line for line in path.read_text(errors="replace").splitlines() if needle in line]

    def close(self):
        with contextlib.suppress(Exception):
            self.driver.close()
            self.result.evidence("blocks", {"count": len(self.driver.blocks), "driver_errors": self.driver.errors[:50],
                                            "built": [[b["at"], b["number"], len(b["transactions"])] for b in self.driver.blocks],
                                            "driver_error_count": len(self.driver.errors),
                                            "with_transactions": sum(1 for b in self.driver.blocks if b["transactions"])})
        with contextlib.suppress(Exception):
            self.client.close()
        with contextlib.suppress(Exception):
            self.result.evidence("client_records", list(self.client.records.values()))
        self.stack.close()


# --- fact latency -------------------------------------------------------------

class VersionProbe:
    """Polls the node's applied fact version every 5 ms (ops_policyStatus)."""

    def __init__(self, live):
        self.live, self.samples, self.changes, self.stopping = live, [], [], threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        target = urllib.parse.urlparse(self.live.stack.node.private_url)
        conn = None
        body = json.dumps({"jsonrpc": "2.0", "id": "live-probe", "method": "ops_policyStatus", "params": []})
        headers = {"Content-Type": "application/json", "Authorization": "Bearer " + self.live.stack.node_token}
        last = None
        while not self.stopping.is_set():
            try:
                conn = conn or http.client.HTTPConnection(target.netloc, timeout=5)
                conn.request("POST", "/", body, headers)
                version = json.loads(conn.getresponse().read())["result"]["version"]
                if version != last:
                    self.samples.append((now(), version))
                    last = version
            except Exception:
                if conn:
                    conn.close()
                conn = None
            self.stopping.wait(.005)

    def applied_at(self, version, after):
        for at, v in self.samples:
            if at >= after and v >= version:
                return at
        return None

    def close(self):
        self.stopping.set()
        self.thread.join(timeout=5)


def fact_change_latency(live, probe, change, label):
    """Make a fact change through the admin API, read the database version
    afterwards (it can only include later changes) and find when the node
    applied it. Returns ms from the request to applied; each sample is also
    kept on the probe with its times."""
    # The clock starts before the request: the admin API answers only after its
    # post-commit work (cache invalidation, audit row), while publication starts
    # at the commit, so the node can apply the change before the answer. The
    # result is an upper bound (it includes the API's own time).
    apply = change.prepare() if hasattr(change, "prepare") else change
    started = now()
    apply()
    answered = now()
    version = live.db_version()
    deadline = now() + 10
    latency = None
    while now() < deadline:
        applied = probe.applied_at(version, started)
        if applied:
            latency = round((applied - started) * 1000, 2)
            break
        time.sleep(.005)
    probe.changes.append({"label": label, "started": round(started, 3), "api_ms": round((answered - started) * 1000, 2),
                          "db_version": version, "latency_ms": latency})
    return latency


class DBVersionStream:
    """The main database's fact version every 50 ms (psql \\watch in the
    container), so every version change, whatever caused it, can be matched to
    when the node applied it."""

    def __init__(self, live):
        self.samples, self.live = [], live
        self.process = subprocess.Popen(["docker", "exec", "-i", live.stack.pg, "psql", "-qtA", "-U", "postgres", "-d", "ops_approvals_demo"],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.process.stdin.write("SELECT version FROM node_policy_clock \\watch 0.05\n")
        self.process.stdin.flush()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        last = None
        for line in self.process.stdout:
            line = line.strip()
            if line.isdigit() and int(line) != last:
                last = int(line)
                self.samples.append((now(), last))

    def lags(self, probe):
        """(first seen in the database, node applied, lag ms) per version."""
        out = []
        for seen, version in self.samples[1:]:
            applied = probe.applied_at(version, seen - 0.05)
            out.append({"version": version, "db_seen": round(seen, 3), "node_applied": applied and round(applied, 3),
                        "lag_ms": applied and round(max(0.0, applied - seen) * 1000, 1)})
        return out

    def close(self):
        with contextlib.suppress(Exception):
            self.process.kill()


class membership_toggler:
    """Alternately removes and restores principal's membership through the
    admin API of base() (default: the first OPS instance). prepare() does the
    reads and returns the single mutating request, so a latency measurement
    times only that request; calling the object does both."""

    def __init__(self, live, principal, base=None):
        self.live, self.principal, self.base, self.member = live, principal, base, True

    def admin(self, method, path, body=None):
        url = self.base() if self.base else self.live.stack.url
        return self.live.request(url + "/api/v1/admin" + path, method, body, self.live.stack.admin_token, True)

    def prepare(self):
        uid = self.principal.uid
        if self.member:
            ids = [m["membership"]["id"] for m in self.admin("GET", f"/users/{uid}/memberships")]

            def apply():
                for membership in ids:
                    self.admin("DELETE", f"/users/{uid}/memberships/{membership}")
        else:
            def apply():
                self.admin("POST", f"/users/{uid}/memberships", {"group_id": self.live.stack.group})
        self.member = not self.member
        return apply

    def __call__(self):
        self.prepare()()


# --- scenarios -----------------------------------------------------------------

def kill_under_load(args, result, sig=signal.SIGKILL, kills=(20, 45, 70), seconds=90, rate=100):
    """L1 (SIGKILL, repeatedly) and L6 (SIGTERM, once): restarts under load."""
    live = Live(args, result, signers=8, per_signer=rate * seconds // 8 + 1)
    try:
        txs = interleave(live.txs.values())[:rate * seconds]
        boots = [live.boot()]
        started = now()
        load = live.load(txs, rate, live.route(), now() + seconds + 120)
        for at in kills:
            time.sleep(max(0, started + at - now()))
            with live.client.lock:
                before = {r["hash"] for r in list(live.client.records.values()) if r.get("accepted_at")}
            result.event("node stop", signal=signal.Signals(sig).name, accepted_so_far=len(before))
            live.stack.node.stop(sig)
            time.sleep(3)
            live.stack.node.start()
            result.event("node started")
            boot = live.wait_until(lambda: (lambda b: b if b and b not in boots else None)(live.boot()), 60, .2)
            boots.append(boot)
        sent = load.join()
        result.event("load done", seconds=round(now() - started, 1))
        accepted, included, tracking = live.outcome_checks(sent, "restarts", settle=180)
        restarts_seen = live.ops_log_lines("execution node restarted")
        result.check("OPS detected every node restart (new boot id) and renewed what the node no longer held",
                     len(restarts_seen) >= len(kills), restarts=len(kills), ops_log_lines=len(restarts_seen))
        renewals = live.renewals()
        result.evidence("identity_history", renewals)
        result.check("renewals after restarts are recorded as system generations (reason node_restarted/undelivered)",
                     renewals.get("actor2:reason41", 0) + renewals.get("actor2:reason40", 0) > 0, history=renewals)
        result.evidence("boots", boots)
    finally:
        live.close()


def outage(args, result):
    """L7 + L8: node down 2 min with pending transactions; one principal banned
    meanwhile. Also L10 (fact change during the recovery burst)."""
    live = Live(args, result, signers=7, per_signer=10, principals=3, reserve=1)
    try:
        a1, a2, banned = live.principals
        spare = live.add_principal(f"did:test:live-{args.scenario}-spare", live.reserved)
        live.wait_facts_current()
        live.driver.pause()
        txs = interleave([live.txs[s] for p in (a1, a2, banned) for s in p.signers])
        futures = live.client.open_loop(txs, 50, live.route(), now() + 30)
        sent = [f.result() for f in futures]
        accepted = [r for r in sent if r.get("accepted_at")]
        result.check("all 60 transactions accepted before the outage", len(accepted) == len(txs), accepted=len(accepted))
        delivered = live.wait_until(lambda: int(live.stack.psql_exec("SELECT count(*) FROM node_tx_binding WHERE state = 1 AND delivered_generation IS NOT NULL")) >= len(txs) or None, 20)
        result.evidence("delivered_before_outage", live.stack.psql_exec("SELECT count(*) FROM node_tx_binding WHERE state = 1 AND delivered_generation IS NOT NULL"))
        live.stack.node.stop(signal.SIGKILL)
        down = now()
        result.event("node killed with pending transactions")
        live.stack.admin("PUT", "/users/" + banned.uid, {"banned": True})
        result.event("principal banned while the node is down", principal=banned.uid)
        time.sleep(max(0, down + 120 - now()))
        probe = VersionProbe(live)
        live.stack.node.start()
        result.event("node restarted after 2 min")
        live.driver.resume()
        # L10: a fact change during the recovery burst.
        time.sleep(1.5)
        toggle = membership_toggler(live, spare)
        burst_latencies = [fact_change_latency(live, probe, toggle, "recovery") for _ in range(2)]
        probe.close()
        result.evidence("fact_latency_during_recovery_ms", burst_latencies)
        result.check("L10: fact change applied by the node within 100 ms during the recovery burst",
                     all(v is not None and v <= 100 for v in burst_latencies), latencies_ms=burst_latencies)
        good = [r for r in accepted if live.owner[r["signer"]] is not banned]
        bad = [r for r in accepted if live.owner[r["signer"]] is banned]
        live.all_settled([r["hash"] for r in good], 120)
        receipts = live.receipts([r["hash"] for r in accepted])
        result.check("L7: every pending transaction of the other principals is included after the outage with no client action",
                     all(is_included(receipts[r["hash"]]) for r in good) and all(len(r["attempts"]) == 1 for r in good),
                     included=sum(1 for r in good if is_included(receipts[r["hash"]])), of=len(good))
        history = live.history()
        restarted = [r for r in good if any(actor == 2 and reason in (40, 41) for _, actor, reason in history.get(r["hash"], []))]
        result.check("L7: every renewal after the restart is in the identity history with a restart reason",
                     len(restarted) == len(good), with_restart_reason=len(restarted), of=len(good),
                     reasons=collections.Counter(reason for r in good for _, actor, reason in history.get(r["hash"], []) if actor == 2))
        time.sleep(5)
        tracking = live.tracking()
        stopped = [r for r in bad if tracking.get(r["hash"], ("",))[:2] == ("binding", 3)]
        reasons = collections.Counter(tracking.get(r["hash"], ("", 0, 0))[2] for r in bad)
        result.check("L8: the banned principal's transactions are not renewed: renewal_stopped with reason principal_banned",
                     len(stopped) == len(bad) and set(reasons) == {20}, stopped=len(stopped), of=len(bad), reasons=dict(reasons))
        result.check("L8: the banned principal's transactions never execute", all(is_absent(receipts[r["hash"]]) for r in bad),
                     not_absent=[(r["hash"], receipts[r["hash"]]) for r in bad if not is_absent(receipts[r["hash"]])])
        renewed_banned = [r["hash"] for r in bad if any(actor == 2 and reason in (40, 41, 42, 43, 44) for _, actor, reason in history.get(r["hash"], []))]
        result.check("L8: no renewal was issued for the banned principal", not renewed_banned, renewed=renewed_banned)
        # Audit (system events sealed into access_logs on the audit database).
        audit_rows = lambda: live.rows("SELECT method, count(*) FROM access_logs WHERE method LIKE 'ops.system.%' GROUP BY 1", "ops_approvals_demo_audit")
        # Wait until the recoveries and the refusals are all sealed (or 60 s).
        sealed = live.wait_until(lambda: (lambda rows: rows if sum(int(c) for m, c in rows if m == "ops.system.recovery") >= len(restarted)
                                          and sum(int(c) for m, c in rows if m in ("ops.system.renewal_refused", "ops.system.renewal_stopped")) >= len(bad) else None)(audit_rows()), 60, 2) or audit_rows()
        result.evidence("audit_system_events", dict((m, int(c)) for m, c in sealed or []))
        recoveries = sum(int(c) for m, c in sealed or [] if m == "ops.system.recovery")
        result.check("L7: every renewal is in the audit log", recoveries >= len(restarted), audited=recoveries, renewals=len(restarted))
        result.check("L8: the stop is audited", any(m == "ops.system.renewal_refused" or m == "ops.system.renewal_stopped" for m, _ in sealed or []),
                     events=dict((m, int(c)) for m, c in sealed or []))
    finally:
        live.close()


def ops_down(args, result):
    """L4: OPS down longer than the fact TTL (30 s): the node stops executing,
    nothing stale executes, and everything resumes when OPS returns."""
    live = Live(args, result, signers=4, per_signer=5)
    try:
        live.driver.pause()
        txs = interleave(live.txs.values())
        sent = [f.result() for f in live.client.open_loop(txs, 50, live.route(), now() + 30)]
        accepted = [r for r in sent if r.get("accepted_at")]
        live.stack.stop_ops(signal.SIGKILL)
        killed = now()
        result.event("OPS killed", accepted=len(accepted))
        stale = live.wait_until(lambda: (lambda v: v if not v[1] else None)(live.node_version()), 60, .5)
        result.check("the node stops being ready once the facts expire", stale is not None and not stale[1],
                     seconds_after_kill=round(now() - killed, 1), status=stale)
        blocks_before = len(live.driver.blocks)
        live.driver.resume()
        time.sleep(15)
        during = live.driver.blocks[blocks_before:]
        executed = [t for b in during for t in b["transactions"]]
        result.check("no transaction executes while the facts are stale", not executed,
                     blocks_built=len(during), transactions=len(executed), driver_errors=len(live.driver.errors))
        live.stack.start_ops()
        result.event("OPS restarted", seconds_down=round(now() - killed, 1))
        live.wait_facts_current(60)
        live.outcome_checks(sent, "after OPS returns", settle=90)
    finally:
        live.close()


def fact_churn(args, result, rate=150, seconds=60):
    """L5: 1 deployment/s + 1 membership change/s while an unaffected
    principal sends load; L10 (under load) via the fact-change latency."""
    live = Live(args, result, signers=10, per_signer=2 * rate * seconds // 8 + 10, principals=1, reserve=2)
    try:
        load_principal = live.principals[0]
        # The deployer and the toggled member have their own wallets.
        extra = live.reserved
        deployer = live.add_principal(f"did:test:live-{args.scenario}-deployer", [extra[0]])
        member = live.add_principal(f"did:test:live-{args.scenario}-member", [extra[1]])
        live.wait_facts_current()
        txs = interleave([live.txs[s] for s in load_principal.signers])
        probe = VersionProbe(live)
        stream = DBVersionStream(live)

        def phase(name, churn):
            batch = txs[:rate * seconds]
            del txs[:rate * seconds]
            latencies, changes = [], []
            stop = threading.Event()

            def churner():
                toggle = membership_toggler(live, member)
                nonce = 0
                while not stop.is_set():
                    started = now()
                    raw = live.h.command(["cast", "mktx", "--private-key", live.keys[extra[0]], "--chain-id", "31337",
                                          "--nonce", str(nonce), "--gas-limit", "200000", "--gas-price", "2000000000", "--legacy", "--create", INIT_CODE])
                    status, payload, _ = live.client.post(live.stack.url + "/rpc/" + live.stack.org, deployer.token,
                                                         json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": [raw]}))
                    changes.append({"deployment": status, "error": payload.get("error") if isinstance(payload, dict) else None})
                    if status == 200 and "error" not in payload:
                        nonce += 1
                    latencies.append(fact_change_latency(live, probe, toggle, name))
                    stop.wait(max(0, 1 - (now() - started)))
            thread = threading.Thread(target=churner, daemon=True) if churn else None
            if thread:
                thread.start()
            records = [f.result() for f in live.client.open_loop(batch, rate, live.route(), now() + seconds + 60)]
            stop.set()
            if thread:
                thread.join()
            first = [r["attempts"][0][1] * 1000 for r in records]
            from_schedule = [(r["attempts"][0][0] + r["attempts"][0][1] - r.get("scheduled", r["attempts"][0][0])) * 1000 for r in records]
            refused = [r for r in records if not r.get("accepted_at") or len(r["attempts"]) > 1]
            summary = {"requests": len(records), "refused_or_resent": len(refused), "latency_ms": {q: percentile(first, v) for q, v in (("p50", .5), ("p95", .95), ("p99", .99))},
                       "latency_from_schedule_ms": {q: percentile(from_schedule, v) for q, v in (("p50", .5), ("p95", .95), ("p99", .99))},
                       "fact_changes": len(latencies), "deployments": collections.Counter(str(c["deployment"]) for c in changes)}
            result.evidence(name, summary)
            return records, summary, latencies

        base_records, base, _ = phase("baseline (no churn)", False)
        churn_records, churn, latencies = phase("fact churn", True)
        probe.close()
        stream.close()
        lags = stream.lags(probe)
        measured_lags = [x["lag_ms"] for x in lags if x["lag_ms"] is not None]
        result.evidence("fact_versions", {"changes": probe.changes, "node_versions": probe.samples, "db_versions": stream.samples, "per_version": lags,
                                          "per_version_summary": {"versions": len(lags), "unapplied": len(lags) - len(measured_lags),
                                                                  "p50": percentile(measured_lags, .5), "p95": percentile(measured_lags, .95), "max": max(measured_lags or [0])}})
        result.check("L5: 0 refusals for the unaffected principal under fact churn", churn["refused_or_resent"] == 0,
                     refused_or_resent=churn["refused_or_resent"], statuses=collections.Counter(str(a[2]) for r in churn_records for a in r["attempts"]))
        added = churn["latency_ms"]["p99"] - base["latency_ms"]["p99"]
        result.check("L5: p99 added latency under fact churn ≤ 250 ms", added <= 250, added_p99_ms=round(added, 1),
                     baseline_p99_ms=round(base["latency_ms"]["p99"], 1), churn_p99_ms=round(churn["latency_ms"]["p99"], 1))
        measured = [v for v in latencies if v is not None]
        p95 = percentile(measured, .95)
        result.evidence("fact_change_to_node_applied_ms", {"samples": len(latencies), "missing": len(latencies) - len(measured),
                                                            "p50": percentile(measured, .5), "p95": p95, "p99": percentile(measured, .99), "max": max(measured or [0])})
        result.check("fact change → node applied p95 ≤ 100 ms (under load, L10)", p95 is not None and p95 <= 100 and len(measured) == len(latencies), p95_ms=p95, samples=len(measured))
        # Revocation: the member's transaction is accepted while a member and
        # refused once removed.
        s = live.stack
        member_route = lambda t: (s.url + "/rpc/" + s.org, member.token)
        if not s.admin("GET", f"/users/{member.uid}/memberships"):
            s.admin("POST", f"/users/{member.uid}/memberships", {"group_id": s.group})
        live.wait_facts_current()
        control = live.client.submit(live.txs[extra[1]][0], member_route, now())
        for m in s.admin("GET", f"/users/{member.uid}/memberships"):
            s.admin("DELETE", f"/users/{member.uid}/memberships/{m['membership']['id']}")
        removed = live.client.submit(live.txs[extra[1]][1], member_route, now())
        result.check("L5: revocation enforced (accepted as a member, refused at once after removal)",
                     bool(control.get("accepted_at")) and not removed.get("accepted_at") and removed["attempts"][-1][2] in (403, 404),
                     member=control["attempts"], removed=removed["attempts"])
        live.outcome_checks(base_records + churn_records, "fact churn", settle=120)
    finally:
        live.close()


def ops_failover(args, result, rate=100, seconds=100):
    """L3 handoffs and L11 crashes at observed intent/renewal barriers.

    The two probe requests are sent once, without client retry. Their saved
    intents are checked separately from the ordinary client-accepted load.
    """
    live = Live(args, result, signers=11, per_signer=rate * seconds // 8 + 1, reserve=1, transport_barriers=True)
    probe = None
    barriers = live.stack.transport_barriers
    try:
        spare = live.add_principal(f"did:test:live-{args.scenario}-spare", live.reserved)
        probe = VersionProbe(live)
        b_url = live.stack.start_extra_ops("b")
        urls = {"a": live.stack.url, "b": b_url}
        alive = {"a": True, "b": True}
        toggle = membership_toggler(live, spare, base=lambda: urls["a" if alive["a"] else "b"])
        result.event("second OPS instance started", url=b_url)

        def route(tx):
            names = [n for n in ("a", "b") if alive[n]]
            name = names[tx["nonce"] % len(names)]
            return urls[name] + "/rpc/" + live.stack.org, live.owner[tx["signer"]].token

        def holder():
            """Identify the real lease backend and its tagged OPS instance."""
            rows = live.rows("SELECT l.pid, a.application_name FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid "
                             "WHERE l.locktype='advisory' AND l.objid=730075 AND l.granted", "ops_approvals_demo")
            if not rows:
                return None
            if len(rows) != 1 or rows[0][1] not in ("ops-live-a", "ops-live-b"):
                raise RuntimeError("cannot map the publisher lease backend to an OPS instance: " + repr(rows))
            return {"pid": int(rows[0][0]), "instance": rows[0][1].removeprefix("ops-live-")}

        def require_wait(predicate, limit, message, step=.1):
            value = live.wait_until(predicate, limit, step)
            if not value:
                raise RuntimeError(message)
            return value

        def binding(tx_hash):
            rows = live.rows("SELECT b.state,b.generation,b.principal_id,b.org_id,b.context_id,"
                             "coalesce(b.delivered_generation,0),coalesce(b.delivered_boot::text,''),"
                             "EXISTS(SELECT 1 FROM node_tx_payload p WHERE p.tx_hash=b.tx_hash AND p.bucket=b.payload_bucket),"
                             "extract(epoch FROM b.created_at),extract(epoch FROM clock_timestamp()) "
                             f"FROM node_tx_binding b WHERE b.tx_hash=decode('{tx_hash[2:]}','hex')")
            if not rows:
                return None
            state, generation, principal, org, context, delivered, boot, payload, created, observed = rows[0]
            return {"hash": tx_hash, "state": int(state), "generation": int(generation), "principal_id": principal,
                    "org_id": org, "context_id": context, "delivered_generation": int(delivered), "delivered_boot": boot,
                    "payload_present": payload == "t", "created_at": float(created), "observed_at": float(observed)}

        windows, published, kills, saved_probes = [], [], [], []
        offset = live.db_now() - now()

        def kill_leader(barrier, target_hash, expected_instance):
            """Keep the killed instance down until the survivor delivers the target."""
            previous = require_wait(holder, 10, "no publisher lease holder before kill")
            name = previous["instance"]
            if name != expected_instance:
                raise RuntimeError("the lease changed before the held sender could be killed")
            alive[name] = False
            killed = now()
            kills.append({**previous, "at": killed + offset})
            if name == "a":
                live.stack.stop_ops(signal.SIGKILL)
            else:
                live.stack.stop_extra_ops("b", signal.SIGKILL)
            # None of the blocked old sender's requests may reach the node.
            barrier.drop_held()
            result.event("OPS leader killed at transport barrier", **previous, target=target_hash)
            current = require_wait(lambda: (lambda h: h if h and h["pid"] != previous["pid"] and h["instance"] != name else None)(holder()),
                                   60, "no different OPS instance took the publisher lease")
            windows.append(round(now() - killed, 2))
            result.event("lease held by survivor", **current, seconds=windows[-1])
            published.append(fact_change_latency(live, probe, toggle, "failover"))
            survivor = current["instance"]
            require_wait(lambda: next((r for r in barrier.snapshot() if r["hash"] == target_hash and r.get("accepted")
                                        and r["instance"] == survivor and r["forwarded_at"] > killed), None),
                         90, "survivor never delivered the barrier's target")
            result.event("survivor delivered target before the old instance restarted", instance=survivor, target=target_hash)
            if name == "a":
                live.stack.start_ops()
            else:
                live.stack.start_extra_ops("b")
            alive[name] = True
            return previous, current, killed

        load_signers, probe_signers = live.principals[0].signers[:8], live.principals[0].signers[8:10]
        txs = interleave([live.txs[s] for s in load_signers])[:rate * seconds]
        started = now()
        load = live.load(txs, rate, route, now() + seconds + 180)
        for at, signer in zip((20, 45), probe_signers):
            time.sleep(max(0, started + at - now()))
            leader = require_wait(holder, 10, "no leader for the saved-intent probe")
            tx = live.txs[signer][0]
            barrier = barriers.arm({tx["raw"]: tx["hash"]})
            pending = live.client.pool.submit(live.client.submit_once, tx, live.route(urls[leader["instance"]]))
            if not barrier.wait(lambda rs: any(r["held"] for r in rs), 20):
                raise RuntimeError("saved-intent request did not reach the pre-forward barrier")
            held = next(r for r in barrier.snapshot() if r["held"])
            stored = binding(tx["hash"])
            status = live.private("ops_transactionStatuses", [[tx["hash"]]])
            node_entry = status.get("result", {}).get("statuses", [None])[0]
            proof = (stored and stored["state"] == 1 and stored["generation"] == 1 and stored["delivered_generation"] == 0
                     and stored["context_id"] == held["context_id"] and stored["principal_id"] == live.owner[signer].uid
                     and stored["org_id"] == live.stack.org and stored["payload_present"] and node_entry == "not_found"
                     and not any(r.get("forwarded_at") for r in barrier.snapshot()))
            result.check("L11: intent and payload committed while its first transport is held before the node", bool(proof),
                         binding=stored, held=held, node_status=node_entry, leader=leader)
            if not proof:
                raise RuntimeError("saved-intent barrier did not establish the required crash window")
            previous, current, killed = kill_leader(barrier, tx["hash"], held["instance"])
            record = pending.result(timeout=10)
            saved_probes.append({"hash": tx["hash"], "signer": signer, "binding_before_kill": stored,
                                 "killed": previous, "survivor": current, "killed_at": killed,
                                 "client": record, "transport": barrier.snapshot()})

        # Hold inclusion until more than one keeper batch has acknowledged
        # pending work. One forwarded renewal plus held transports and still-
        # unrenewed bindings prove that the next kill is inside actual renewal.
        live.driver.pause()
        acknowledged_sql = ("SELECT encode(tx_hash,'hex'),generation,context_id FROM node_tx_binding "
                            "WHERE state=1 AND delivered_generation=generation ORDER BY created_at LIMIT 1024")
        backlog = require_wait(lambda: (lambda rows: rows if len(rows) == 1024 else None)(live.rows(acknowledged_sql)),
                               45, "not enough acknowledged pending intents for a split renewal batch", .5)
        by_hash = {tx["hash"]: tx for group in live.txs.values() for tx in group}
        targets = {"0x" + hx: int(generation) for hx, generation, _ in backlog}
        barrier = barriers.arm({by_hash[h]["raw"]: h for h in targets}, allow=1)
        node_stop = now() + offset
        live.stack.node.stop(signal.SIGTERM)
        time.sleep(2)
        live.stack.node.start()
        new_boot = require_wait(live.boot, 15, "restarted node has no boot id")
        result.event("node restarted with a paused inclusion backlog", pending=len(targets), boot_id=new_boot)
        if not barrier.wait(lambda rs: any(r.get("accepted") and r.get("boot_id") == new_boot for r in rs)
                            and any(r["held"] for r in rs), 30):
            raise RuntimeError("no completed and blocked recovery transports before the kill")
        held = next(r for r in barrier.snapshot() if r["held"])
        stored = binding(held["hash"])
        values = ",".join(f"(decode('{h[2:]}','hex'),{generation})" for h, generation in targets.items())
        unrenewed = int(live.stack.psql_exec("WITH targets(hash,generation) AS (VALUES " + values + ") "
                                            "SELECT count(*) FROM targets t JOIN node_tx_binding b ON b.tx_hash=t.hash "
                                            "WHERE b.generation=t.generation"))
        before = live.system_rows_between(node_stop, now() + offset + 1, [40, 41])
        proof = (stored and stored["context_id"] == held["context_id"] and stored["generation"] > targets[held["hash"]]
                 and before > 0 and unrenewed > 0)
        result.check("L11: recovery has a completed transport, a saved blocked generation and unrenewed work before the leader kill",
                     bool(proof), binding=stored, held=held, system_generations_before=before, unrenewed=unrenewed,
                     transport=barrier.snapshot())
        if not proof:
            raise RuntimeError("recovery barrier did not establish an interruption during renewal")
        previous, current, killed = kill_leader(barrier, held["hash"], held["instance"])
        after = require_wait(lambda: live.system_rows_between(killed + offset, now() + offset + 1, [40, 41]) or None,
                             60, "survivor issued no generation after the mid-renewal kill")
        result.check("L11: survivor continued renewal after the interrupted batch", before > 0 and after > 0,
                     before_kill=before, after_kill=after, killed=previous, survivor=current)
        result.evidence("mid_recovery_transport", barrier.snapshot())
        live.driver.resume()
        sent = load.join()
        probe.close()
        probe = None
        result.check("L3: the lease is taken over within a bounded window after each leader kill",
                     all(w <= 15 for w in windows), windows_s=windows, kills=kills)
        result.check("L3: fact publication continues on each new leader (a change applied within 100 ms)",
                     all(v is not None and v <= 100 for v in published), latencies_ms=published)
        live.outcome_checks(sent, "failover", settle=240)
        saved_hashes = [p["hash"] for p in saved_probes]
        tracking = live.all_settled(saved_hashes, 120)
        receipts = live.receipts(saved_hashes)
        rows = live.final_rows_per_hash()
        bad, unanswered = live.identities_of_included([(p["hash"], p["signer"]) for p in saved_probes])
        for p in saved_probes:
            first = next((r for r in p["transport"] if r.get("accepted")), None)
            correct = (len(p["client"]["attempts"]) == 1 and not p["client"].get("accepted_at")
                       and tracking.get(p["hash"], ("", 0))[:2] == ("final", 10)
                       and is_included(receipts.get(p["hash"])) and rows.get(p["hash"]) == 1
                       and first and first["instance"] == p["survivor"]["instance"]
                       and all(not r.get("forwarded_at") for r in p["transport"] if r["held"]))
            result.check("L11: survivor executes the saved intent once with one client attempt and no old-sender forwarding",
                         bool(correct and not bad and not unanswered), hash=p["hash"], client=p["client"],
                         tracking=tracking.get(p["hash"]), receipt=receipts.get(p["hash"]), first_node_forward=first)
        result.evidence("saved_intent_probes", saved_probes)
        result.evidence("identity_history", live.renewals())
    finally:
        if probe:
            probe.close()
        for barrier in barriers.barriers:
            barrier.drop_held()
        live.close()


def congestion(args, result):
    """L9 (congestion within the pending-work limit) and L13 (burst above the
    limit, then a full inclusion stall), with the plan's arithmetic scaled down
    as in TestCongestionRenewalSimulation: lease 120 s, maximum age 240 s,
    renewal budget 20/s, 5 transactions per block."""
    gas = TX_GAS + 21_000 * 4  # a 300k-gas transfer fits while ≥ 300k remain: 5 per block
    env = {"OPS_NODE_POLICY_TRANSACTION_IDENTITY_TTL": "120s", "OPS_NODE_POLICY_MAX_AGE": "240s",
           "OPS_NODE_POLICY_RENEWAL_BUDGET": "20", "OPS_NODE_POLICY_EXPECTED_TPS": "5", "OPS_NODE_POLICY_INCLUSION_BOUND": "1.5s",
           "OPS_NODE_POLICY_BLOCK_GAS_LIMIT": str(gas),
           # L_admit = 20 × (60 − 30) − 2 × ⌊gas / 21,000⌋ = 564: the per-principal and
           # per-organization caps are raised to it so the global limit binds (one principal).
           "OPS_NODE_POLICY_PRINCIPAL_PENDING_LIMIT": "564", "OPS_NODE_POLICY_ORG_PENDING_LIMIT": "564"}
    live = Live(args, result, ops_env=env, gas_limit=gas, signers=50, per_signer=120)
    try:
        plan = live.ops_log_lines("node policy lease keeper")
        result.evidence("keeper_plan", plan[-1][:600] if plan else None)
        limit = int(plan[-1].split("pending_limit=")[1].split()[0]) if plan else None
        signer_list = sorted(live.txs, key=lambda s: int(live.keys[s], 16))
        sampler_stop = threading.Event()
        samples = []

        def sampler():
            while not sampler_stop.is_set():
                with contextlib.suppress(Exception):
                    # Columns: pending; past their lease; past a lease that is not the
                    # maximum-age cap (a lapse: the cap is created + 240 s truncated to
                    # the second, and the stop follows within a tick); lease_expiring
                    # renewals so far; the global pending-work counter.
                    row = live.stack.psql_exec("SELECT (SELECT count(*) FROM node_tx_binding WHERE state = 1), "
                                               "(SELECT count(*) FROM node_tx_binding WHERE state = 1 AND expires_at < clock_timestamp()), "
                                               "(SELECT count(*) FROM node_tx_binding WHERE state = 1 AND expires_at < clock_timestamp() AND expires_at < created_at + interval '239 seconds'), "
                                               "(SELECT count(*) FROM node_tx_identities WHERE actor = 2 AND reason = 44), "
                                               "(SELECT used FROM pending_quota)").split("|")
                    samples.append([round(now(), 1)] + [int(x) for x in row])
                sampler_stop.wait(1)
        threading.Thread(target=sampler, daemon=True).start()
        # L9: 10 signers × 120 = 1,200 transactions at 8/s against 5/s inclusion.
        l9 = interleave([live.txs[s] for s in signer_list[:10]])[:1200]
        l9_start = now()
        records = [f.result() for f in live.client.open_loop(l9, 8, live.route(), now() + 400)]
        result.event("L9 load sent", seconds=round(now() - l9_start, 1))
        tracking = live.all_settled([r["hash"] for r in records], 400)
        l9_samples = [s for s in samples if s[0] >= l9_start]
        renewals_l9 = live.renewals({r["hash"] for r in records})
        elapsed = now() - l9_start
        receipts = live.receipts([r["hash"] for r in records])
        result.evidence("L9_samples", l9_samples)
        result.check("L9: the sampler covered the phase (≥ 1 sample per 2 s)", len(l9_samples) >= elapsed / 2, samples=len(l9_samples))
        result.check("L9: every transaction included, no sender held back", all(is_included(receipts[r["hash"]]) for r in records) and all(r.get("accepted_at") for r in records),
                     included=sum(1 for r in records if is_included(receipts[r["hash"]])), of=len(records))
        result.check("L9: pending work stays within the limit", max((s[1] for s in l9_samples), default=0) <= (limit or 0),
                     peak_pending=max((s[1] for s in l9_samples), default=0), limit=limit)
        result.check("L9: zero lease gaps (no pending identity past its lease before the maximum age)",
                     max((s[3] for s in l9_samples), default=0) == 0, peak_expired=max((s[2] for s in l9_samples), default=0))
        lease_renewals = renewals_l9.get("actor2:reason44", 0)
        excess = budget_excess(l9_samples, 20)
        result.check("L9: renewals happened and stayed within the budget (20/s with a 2 s burst, any window ≥ 5 s)", lease_renewals > 0 and excess <= 5,
                     renewals=lease_renewals, seconds=round(elapsed, 1), worst_excess=round(excess, 1), history=renewals_l9)
        # L13: 40 signers at 40/s for 60 s against 5/s inclusion, then a full stall.
        l13 = interleave([live.txs[s] for s in signer_list[10:]])[:2400]
        l13_start = now()
        # Sent once each (no resend after a refusal), so the offered rate is exact.
        burst = live.client.open_loop(l13, 40, live.route(), now())
        records13 = [f.result() for f in burst]
        result.event("L13 burst sent", seconds=round(now() - l13_start, 1))
        statuses = collections.Counter(str(a[2]) for r in records13 for a in r["attempts"])
        burst_samples = [s for s in samples if s[0] >= l13_start]
        result.check("L13: backpressure at the limit (503/429 refusals; pending never above it)",
                     (statuses.get("503", 0) + statuses.get("429", 0)) > 0 and max((s[5] for s in burst_samples), default=0) <= (limit or 0),
                     statuses=dict(statuses), peak_quota=max((s[5] for s in burst_samples), default=0), limit=limit)
        live.driver.pause()
        stall = now()
        result.event("inclusion stalled")
        accepted13 = [r for r in records13 if r.get("accepted_at")]
        pending13 = lambda: {x for x, v in live.tracking().items() if v[:2] == ("binding", 1)} & {r["hash"] for r in accepted13}
        live.wait_until(lambda: not pending13() or None, 420, 5)
        tracking = live.tracking()
        on_chain = live.receipts([r["hash"] for r in accepted13])
        # Stalled: accepted, never included (a provisional row at the stall was
        # included in the last blocks before it).
        stalled = [r for r in accepted13 if is_absent(on_chain.get(r["hash"], {"error": "missing"}))]
        reasons = collections.Counter(tracking[r["hash"]][1:3] for r in stalled)
        stall_samples = [s for s in samples if s[0] >= stall]
        result.check("L13: under the stall, renewal_stopped at the maximum age (not before)", set(reasons) <= {(3, 8)} and stalled,
                     stopped=dict((f"{k}", v) for k, v in reasons.items()), seconds_stalled=round(now() - stall, 1))
        renewals13 = live.renewals({r["hash"] for r in accepted13})
        excess13 = budget_excess([s for s in samples if s[0] >= l13_start], 20)
        result.check("L13: the sampler covered the stall (≥ 1 sample per 2 s)", len(stall_samples) >= (now() - stall) / 2, samples=len(stall_samples))
        result.check("L13: no renewal debt beyond the budget (renewals ≤ budget per interval; no lapse before the maximum age)",
                     excess13 <= 5 and max((s[3] for s in stall_samples), default=0) == 0,
                     renewals=renewals13, worst_excess=round(excess13, 1), peak_lapsed_before_max_age=max((s[3] for s in stall_samples), default=0))
        result.evidence("L13_samples", [s for s in samples if s[0] >= l13_start])
        # Dropped only on finalized nonce evidence: a competitor takes one stopped
        # transaction's nonce, the others keep theirs.
        nonces_on_chain = {}
        victim = None
        for r in sorted(stalled, key=lambda r: (r["signer"], r["nonce"])):
            if r["signer"] not in nonces_on_chain:
                nonces_on_chain[r["signer"]] = int(live.stack.node.rpc("eth_getTransactionCount", r["signer"], "latest"), 16)
            if r["nonce"] == nonces_on_chain[r["signer"]]:
                victim = r
                break
        result.evidence("victim", victim and {"hash": victim["hash"], "signer": victim["signer"], "nonce": victim["nonce"]})
        raw = live.h.command(["cast", "mktx", TARGET, "--value", "1", "--private-key", live.keys[victim["signer"]], "--chain-id", "31337",
                              "--nonce", str(victim["nonce"]), "--gas-limit", "21000", "--gas-price", "3000000000", "--legacy"])
        competitor = live.h.command(["cast", "keccak", raw]).lower()
        live.driver.resume()
        record = live.client.submit({"hash": competitor, "raw": raw, "signer": victim["signer"], "nonce": victim["nonce"]}, live.route(), now() + 60)
        result.event("competitor sent", accepted=bool(record.get("accepted_at")), hash=competitor)
        dropped = live.wait_until(lambda: live.tracking().get(victim["hash"], ("",))[:2] == ("final", 12) or None, 240, 3)
        tracking = live.tracking()
        others = [r for r in stalled if r is not victim]
        other_states = collections.Counter(f"{tracking.get(r['hash'], ('?',))[0]}:{tracking.get(r['hash'], ('', '?'))[1]}" for r in others)
        result.check("L13: dropped only for the transaction whose nonce a finalized competitor used",
                     bool(dropped) and not any(tracking.get(r["hash"], ("", 0))[:2] == ("final", 12) for r in others),
                     victim_state=tracking.get(victim["hash"]), competitor_receipt=live.receipts([competitor]).get(competitor), others=dict(other_states))
        sampler_stop.set()
    finally:
        live.close()


def reorg(args, result):
    """L12: a rival block omits an already processed transaction (a contract
    creation): the row returns to pending, re-executes and finalizes once;
    ownership is registered only after finality, once."""
    live = Live(args, result, signers=2, per_signer=3, finality_lag=4)
    try:
        principal = live.principals[0]
        signer = principal.signers[0]
        raw = live.h.command(["cast", "mktx", "--private-key", live.keys[signer], "--chain-id", "31337",
                              "--nonce", "0", "--gas-limit", "200000", "--gas-price", "2000000000", "--legacy", "--create", INIT_CODE])
        tx_hash = live.h.command(["cast", "keccak", raw]).lower()
        created = live.h.command(["cast", "compute-address", signer, "--nonce", "0"]).split()[-1].lower()
        live.driver.pause()
        record = live.client.submit({"hash": tx_hash, "raw": raw, "signer": signer, "nonce": 0}, live.route(), now() + 30)
        result.check("deployment accepted", bool(record.get("accepted_at")), attempts=record["attempts"])
        # One block holding it; then hold the head until OPS records it as provisional.
        with live.driver.lock:
            block = live.driver.build(live.stack.node.head, .8)
        result.event("block with the deployment", number=block["number"], transactions=block["transactions"])
        provisional = live.wait_until(lambda: live.tracking().get(tx_hash, ("",))[:2] == ("binding", 2) or None, 30, .5)
        owner_rows = lambda: int(live.stack.psql(f"SELECT count(*) FROM contracts WHERE lower(address) = '{created}'"))
        result.check("OPS saw the deployment as provisional (not final) before the reorg", bool(provisional),
                     tracking=live.tracking().get(tx_hash), ownership_rows=owner_rows())
        result.check("no ownership registered before finality", owner_rows() == 0, rows=owner_rows())
        replaced, rival = live.driver.reorg()
        result.event("reorg", replaced=replaced["hash"], rival=rival["hash"], rival_transactions=rival["transactions"])
        result.check("the rival block omits the processed transaction", tx_hash not in rival["transactions"], rival=rival)
        back = live.wait_until(lambda: live.tracking().get(tx_hash, ("",))[:2] == ("binding", 1) or None, 30, .2)
        result.check("the row returns to pending after the reorg", bool(back), tracking=live.tracking().get(tx_hash))
        live.driver.resume()
        final = live.wait_until(lambda: live.tracking().get(tx_hash, ("",))[0] == "final" or None, 120, 1)
        receipt = live.receipts([tx_hash])[tx_hash]
        result.check("re-executes on the canonical chain and finalizes once", bool(final) and receipt and receipt["status"] == "0x1"
                     and live.final_rows_per_hash().get(tx_hash) == 1 and receipt["hash"] != replaced["hash"],
                     tracking=live.tracking().get(tx_hash), receipt=receipt, final_rows=live.final_rows_per_hash().get(tx_hash))
        rows = live.rows(f"SELECT org_id FROM contracts WHERE lower(address) = '{created}'", "ops_approvals_demo")
        result.check("ownership registered once, for the deploying organization, after finality", len(rows) == 1 and rows[0][0] == live.stack.org,
                     rows=rows, org=live.stack.org)
    finally:
        live.close()


SCENARIOS = {
    "kill-under-load": lambda a, r: kill_under_load(a, r),                                            # L1
    "graceful-restart": lambda a, r: kill_under_load(a, r, sig=signal.SIGTERM, kills=(25,), seconds=60),  # L6
    "outage": outage,                                                                                  # L7, L8, L10
    "ops-down": ops_down,                                                                              # L4
    "fact-churn": fact_churn,                                                                          # L5, L10
    "ops-failover": ops_failover,                                                                      # L3, L11
    "congestion": congestion,                                                                          # L9, L13
    "reorg": reorg,                                                                                    # L12
}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    result = Result(args.output / "result.json", args.scenario)
    try:
        SCENARIOS[args.scenario](args, result)
    except BaseException as error:
        result.check("scenario completed without an error", False, error=f"{type(error).__name__}: {error}")
        raise
    finally:
        result.data["ended"] = now()
        result.save()
    sys.exit(0 if result.data["passed"] else 1)


if __name__ == "__main__":
    main()
