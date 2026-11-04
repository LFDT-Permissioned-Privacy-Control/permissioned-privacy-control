#!/usr/bin/env python3
"""V2 stack for transactions.py --node reth-v2: guarded ops-reth + OPS in Reth policy mode.

Same PostgreSQL/Redis containers, OPS settings, Gasstorm fixture seed and
Engine API block driver as the V1 stack. Only the node (ops-reth, policy
enforced in the node, no preflight) and OPS's execution mode differ.
"""
import base64
import contextlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

import harness as h
from demo import request, docker
import gasstorm_compare as g

REVIEWERS = ("did:test:perf-policy-author", "did:test:perf-policy-reviewer")
V2_BINARY = Path(os.environ.get("OPS_RETH_V2_BINARY", str(h.ROOT / "node/reth/target/release/ops-reth")))
OPS_V2_BINARY = Path(os.environ.get("OPS_SERVER_BINARY", str(h.ROOT / ".tmp/ops-server")))


class V2Node(h.Node):
    """ops-reth without --dev: blocks come only from the Engine API driver."""

    def __init__(self, name, deployment, public_key, token):
        self.name, self.fork = name, "shanghai"
        self.directory = Path(tempfile.mkdtemp(prefix=name + "-", dir=h.SCRATCH))
        self.log_path, self.stdout_path = self.directory / "node.log", self.directory / "node-stdout.log"
        self.rpc_url = "http://127.0.0.1:" + str(h.unused_port())
        self.engine_url = "http://127.0.0.1:" + str(h.unused_port())
        self.private_url = "http://127.0.0.1:" + str(h.unused_port())
        self.metrics_address = "127.0.0.1:" + str(h.unused_port())
        self.secret = bytes.fromhex("11" * 32)
        jwt_path = self.directory / "jwt.hex"
        jwt_path.write_text(self.secret.hex())
        self.records, self.rpc_local, self.rpc_connections = [], threading.local(), []
        self.rpc_connections_lock = threading.Lock()
        self.state_dir = self.directory / "policy"
        self.approval_port = None
        self.log, self.stdout = self.log_path.open("w"), self.stdout_path.open("w")
        args = [str(V2_BINARY), "node", "--chain", str(h.EVIDENCE / "genesis.json"), "--datadir", str(self.directory / "data"),
                "--http", "--http.addr", "127.0.0.1", "--http.port", self.rpc_url.rsplit(":", 1)[1], "--http.api", "eth,web3,net,txpool",
                "--authrpc.addr", "127.0.0.1", "--authrpc.port", self.engine_url.rsplit(":", 1)[1], "--authrpc.jwtsecret", str(jwt_path),
                "--disable-discovery", "--addr", "127.0.0.1", "--port", "0", "--max-outbound-peers", "0", "--max-inbound-peers", "0",
                "--txpool.max-account-slots", "1024", "--log.stdout.format", "terminal", "--log.file.directory", str(self.directory / "logs"),
                "--metrics", self.metrics_address]
        if gas_limit := os.environ.get("OPS_POC_GAS_LIMIT"):
            args.extend(["--builder.gaslimit", str(int(gas_limit))])
        if connections := os.environ.get("OPS_POC_RPC_MAX_CONNECTIONS"):
            args.extend(["--rpc.max-connections", str(int(connections))])
        # Production default: per-decision logging off, unless explicitly asked for.
        self.decision_log = os.environ.get("OPS_POC_V2_DECISION_LOG") == "1"
        env = dict(os.environ, RUST_LOG="info", OPS_POLICY_DECISION_LOG="1" if self.decision_log else "0", OPS_NODE_POLICY_CHAIN_ID="31337", OPS_NODE_POLICY_DEPLOYMENT_ID=deployment,
                   OPS_NODE_POLICY_PUBLIC_KEYS=json.dumps({"perf": public_key}), OPS_NODE_POLICY_LISTEN=self.private_url.removeprefix("http://"),
                   OPS_NODE_POLICY_TOKEN=token, OPS_NODE_POLICY_STATE_DIR=str(self.state_dir))
        self.args, self.env = args, env
        self.spawn()
        try:
            self.wait_rpc()
            self.head = self.rpc("eth_getBlockByNumber", "latest", False)
            assert int(self.head["number"], 16) == 0
        except BaseException:
            self.close()
            raise

    def spawn(self):
        self.process = subprocess.Popen(self.args, cwd=h.ROOT, env=self.env, stdout=self.stdout, stderr=self.log,
                                        start_new_session=os.environ.get("OPS_POC_DETACH_CHILDREN") == "1")

    def wait_rpc(self):
        for _ in range(600):
            if self.process.poll() is not None:
                raise RuntimeError((self.stdout_path.read_text() + self.log_path.read_text())[-8000:])
            try:
                self.rpc("web3_clientVersion")
                return
            except (OSError, urllib.error.URLError, RuntimeError):
                time.sleep(0.1)
        raise RuntimeError("ops-reth startup timed out")

    def stop(self, sig=signal.SIGKILL, timeout=60):
        """Stop the node process: SIGKILL is a crash, SIGTERM a clean stop."""
        if self.process.poll() is None:
            self.process.send_signal(sig)
            self.process.wait(timeout=timeout)
        # Keep-alive connections to the stopped process are dead.
        with self.rpc_connections_lock:
            for connection in self.rpc_connections:
                connection.close()
            self.rpc_connections.clear()
        self.rpc_local = threading.local()

    def start(self):
        """Start again on the same data and policy state directories and ports
        (live acceptance: restarts and outages)."""
        self.spawn()
        self.wait_rpc()
        self.head = self.rpc("eth_getBlockByNumber", "latest", False)

    def archive_bytes(self):
        # The running node writes and prunes meanwhile: skip what vanished.
        total = 0
        for path in self.state_dir.rglob("*"):
            try:
                total += path.stat().st_size if path.is_file() else 0
            except FileNotFoundError:
                pass
        return total


class V2Stack(g.GasstormStack):
    """GasstormStack's seed and RPC helpers over a V2 node and OPS in Reth mode."""

    def __init__(self, name, ops_env=None, transport_barriers=False):
        self.cached_contracts, self.rpc_local, self.rpc_connections = {}, threading.local(), []
        self.rpc_connections_lock = threading.Lock()
        self.name, self.disabled, self.containers, self.node, self.ops = name, False, [], None, None
        self.transport_barriers = None
        self.directory = h.SCRATCH / (name + "-" + str(time.time_ns()))
        self.directory.mkdir(parents=True)
        self.admin_token, self.tokens = "ops-reth-local-demo-only", {}
        self.ops_binary = OPS_V2_BINARY
        try:
            prefix = "ops-approvals-" + str(time.time_ns())
            pg = docker("run", "-d", "--rm", "--name", prefix + "-pg", "--label", "ops-approvals-demo=true",
                        "-e", "POSTGRES_PASSWORD=postgres", "-e", "POSTGRES_DB=ops_approvals_demo",
                        "-e", "AUDIT_APP_PASSWORD=audit-demo-only", "-p", "127.0.0.1::5432",
                        "-v", str(h.ROOT / "scripts/init-audit-db.sh") + ":/docker-entrypoint-initdb.d/10-audit.sh:ro",
                        "-v", str(h.ROOT / "scripts/init-exec-db.sh") + ":/docker-entrypoint-initdb.d/20-exec.sh:ro", "postgres:15-alpine")
            self.containers.append(pg)
            self.pg = pg
            pgport = docker("port", pg, "5432/tcp").rsplit(":", 1)[1]
            for _ in range(200):
                if subprocess.run(["docker", "exec", pg, "pg_isready", "-U", "postgres"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                    break
                time.sleep(.1)
            else:
                raise RuntimeError("Postgres startup failed")
            redis = docker("run", "-d", "--rm", "--name", prefix + "-redis", "--label", "ops-approvals-demo=true",
                           "-p", "127.0.0.1::6379", "redis:7-alpine", "redis-server", "--requirepass", "redis-demo-only")
            self.containers.append(redis)
            redisport = docker("port", redis, "6379/tcp").rsplit(":", 1)[1]
            key = Ed25519PrivateKey.generate()
            seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            seed_file = self.directory / "policy-key"
            seed_file.write_text(base64.b64encode(seed).decode() + "\n")
            seed_file.chmod(0o600)
            deployment, token = "perf-" + secrets.token_hex(4), secrets.token_hex(24)
            self.node = V2Node(name, deployment, base64.b64encode(public).decode(), token)
            self.node_token, self.extra_ops = token, {}
            if transport_barriers:
                from transport_barrier import NodeTransportBarriers
                self.transport_barriers = NodeTransportBarriers(self.node.private_url)
            self.url = "http://127.0.0.1:" + str(h.unused_port())
            env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "TMPDIR", "LANG")}
            env.update(ENVIRONMENT="development", GIN_MODE="release", PORT=self.url.rsplit(":", 1)[1], BASE_URL=self.url,
                       NODE_URL=self.node.rpc_url, DATABASE_URL=f"postgres://postgres:postgres@127.0.0.1:{pgport}/ops_approvals_demo?sslmode=disable",
                       AUDIT_DATABASE_URL=f"postgres://privacy_proxy_app:audit-demo-only@127.0.0.1:{pgport}/ops_approvals_demo_audit?sslmode=disable",
                       REDIS_URL=f"redis://:redis-demo-only@127.0.0.1:{redisport}/0",
                       JWT_SECRET="ops-reth-demo-access-secret-at-least-32-bytes", JWT_REFRESH_SECRET="ops-reth-demo-refresh-secret-at-least-32-bytes",
                       ADMIN_API_TOKEN=self.admin_token, ALLOW_MOCK_LOGIN="true", MOCK_SIGNATURES="false", ENABLE_TRAVEL_RULE="true",
                       VERIFIER_ID="did:privado:verifier:dev-0000000000000000", DISABLE_COINGECKO="true",
                       MAX_CONCURRENT_REQUESTS="5000", EXPLORER_DATABASE_URL="", TRACE_TIERED_VALIDATION="false",
                       AUDIT_BUFFER_DIR=str(self.directory / "audit-buffer"), DB_MAX_OPEN_CONNS="30",
                       OPS_NODE_POLICY_MODE="reth", OPS_NODE_POLICY_URL=self.node.private_url, OPS_NODE_POLICY_TOKEN=token,
                       OPS_NODE_POLICY_PRIVATE_KEY_FILE=str(seed_file), OPS_NODE_POLICY_KEY_ID="perf",
                       OPS_NODE_POLICY_CHAIN_ID="31337", OPS_NODE_POLICY_DEPLOYMENT_ID=deployment,
                       PLATFORM_ADMIN_SUBJECTS=",".join(REVIEWERS))
            env.update({k: v for k, v in (ops_env or {}).items() if not k.startswith("OPS_APPROVAL_")})
            if self.transport_barriers:
                env["OPS_NODE_POLICY_URL"] = self.transport_barriers.endpoint("a")
                env["DATABASE_URL"] = self.instance_database_url(env["DATABASE_URL"], "a")
            self.ops_environment = env
            self.opslog = (self.directory / "ops.log").open("w")
            self.ops = self.spawn_ops(env, self.opslog, self.url, self.directory / "ops.log")
            self.seed()
            self.activate_execution_policy()
            # Blocks may only be built once the node holds fresh facts for the
            # seeded configuration; the driver starts after this returns.
            for _ in range(600):
                try:
                    request(self.url + "/ready")
                    break
                except (OSError, RuntimeError):
                    time.sleep(.1)
            else:
                raise RuntimeError("OPS never reported ready (node facts)")
            (self.directory / "connections.json").write_text(json.dumps({"ops": self.url, "reth": self.node.rpc_url, "private": self.node.private_url,
                                                                       "node_directory": str(self.node.directory), "postgres": pg, "redis": redis}, indent=2))
        except BaseException:
            self.close()
            raise

    def spawn_ops(self, env, log, url, log_path):
        process = subprocess.Popen([str(self.ops_binary)], cwd=self.directory, env=env, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=os.environ.get("OPS_POC_DETACH_CHILDREN") == "1")
        for _ in range(300):
            if process.poll() is not None:
                raise RuntimeError(log_path.read_text()[-7000:])
            try:
                request(url + "/health")
                return process
            except (OSError, RuntimeError):
                time.sleep(.1)
        process.kill()
        process.wait(timeout=5)
        raise RuntimeError("OPS startup timed out")

    def stop_ops(self, sig=signal.SIGKILL):
        """Stop the first OPS instance (SIGKILL: crash)."""
        if self.ops.poll() is None:
            self.ops.send_signal(sig)
            self.ops.wait(timeout=30)

    def start_ops(self):
        """Start the first OPS instance again with the same settings, port and audit buffer."""
        self.ops = self.spawn_ops(self.ops_environment, self.opslog, self.url, self.directory / "ops.log")

    def start_extra_ops(self, name):
        """A further OPS instance on the same databases and node (its own port
        and audit buffer); restarting the same name reuses both. Returns its URL."""
        if name in self.extra_ops:
            url, env, log, _ = self.extra_ops[name]
        else:
            url = "http://127.0.0.1:" + str(h.unused_port())
            env = dict(self.ops_environment, PORT=url.rsplit(":", 1)[1], BASE_URL=url,
                       AUDIT_BUFFER_DIR=str(self.directory / ("audit-buffer-" + name)))
            if self.transport_barriers:
                env["OPS_NODE_POLICY_URL"] = self.transport_barriers.endpoint(name)
                env["DATABASE_URL"] = self.instance_database_url(env["DATABASE_URL"], name)
            log = (self.directory / f"ops-{name}.log").open("w")
            # Registered before the start, so close() also closes a failed one's log.
            self.extra_ops[name] = (url, env, log, None)
        process = self.spawn_ops(env, log, url, self.directory / f"ops-{name}.log")
        self.extra_ops[name] = (url, env, log, process)
        return url

    @staticmethod
    def instance_database_url(url, name):
        """Tag the real publisher backend so a crash targets its actual owner."""
        parts = urllib.parse.urlsplit(url)
        query = dict(urllib.parse.parse_qsl(parts.query))
        query["application_name"] = "ops-live-" + name
        return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))

    def stop_extra_ops(self, name, sig=signal.SIGKILL):
        url, env, log, process = self.extra_ops[name]
        if process is not None and process.poll() is None:
            process.send_signal(sig)
            process.wait(timeout=30)

    def activate_execution_policy(self):
        """V2 executes only under an active, reviewed execution policy. Import
        the org's configuration as the baseline policy and activate it with two
        administrators (author submits, reviewer activates), as the V2
        acceptance stack does (scripts/ops-reth-stack/acceptance.py)."""
        group = self.admin("POST", f"/orgs/{self.org}/groups", {"slug": "reviewers", "name": "Reviewers", "is_org_admin": True})["id"]
        self.admin("PUT", f"/orgs/{self.org}/groups/{group}/access", {"allowed_methods": ["*"], "claims": []})
        tokens = []
        for did in REVIEWERS:
            self.login(did)
            onboard = self.admin("POST", f"/orgs/{self.org}/memberships/by-did", {"did": did, "group_id": group})
            self.admin("PUT", "/users/" + onboard["user_id"], {"kyc": True})
            tokens.append(self.login(did))
        author, reviewer = tokens
        prefix = f"{self.url}/api/v1/admin/orgs/{self.org}/configuration/execution-rules"
        source = request(prefix + "/context", token=author)["source"]
        candidate = request(prefix + "/revisions", "POST", source, author)
        request(prefix + "/revisions/" + candidate["id"] + "/simulate", "POST", {"coactivate": []}, reviewer)
        request(prefix + "/revisions/" + candidate["id"] + "/activate", "POST", {"coactivate": []}, reviewer)
        self.policy_digest = candidate.get("digest")

    def psql(self, sql, database="ops_approvals_demo"):
        return subprocess.check_output(["docker", "exec", self.pg, "psql", "-qtA", "-U", "postgres", "-d", database, "-c", sql], text=True).strip()

    def psql_exec(self, sql):
        """Query the execution-tracking database (derived <name>_exec, RD-1410)."""
        return self.psql(sql, "ops_approvals_demo_exec")

    def close(self):
        # Every step runs even if an earlier one fails: containers must never outlive a run.
        try:
            for name, (_, _, log, process) in getattr(self, "extra_ops", {}).items():
                # One instance failing to stop never skips the others or the first.
                try:
                    if process is not None and process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                except Exception:
                    pass
                finally:
                    log.close()
                    with contextlib.suppress(OSError):
                        shutil.copy2(self.directory / f"ops-{name}.log", h.EVIDENCE / (f"{self.name}-ops-{name}.log"))
            if self.ops is None and getattr(self, "opslog", None) is not None:
                # OPS never came up: keep its log as evidence, as before.
                self.opslog.close()
                with contextlib.suppress(OSError):
                    shutil.copy2(self.directory / "ops.log", h.EVIDENCE / (self.name + "-ops.log"))
            if self.ops is not None:
                try:
                    self.ops.terminate()
                    try:
                        self.ops.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        self.ops.kill()
                        self.ops.wait(timeout=5)
                finally:
                    self.opslog.close()
                    shutil.copy2(self.directory / "ops.log", h.EVIDENCE / (self.name + "-ops.log"))
        finally:
            try:
                try:
                    if self.transport_barriers:
                        self.transport_barriers.close()
                finally:
                    if self.node is not None:
                        self.node.close()
            finally:
                for container in reversed(self.containers):
                    subprocess.run(["docker", "stop", "-t", "3", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                for connection in self.rpc_connections:
                    connection.close()
