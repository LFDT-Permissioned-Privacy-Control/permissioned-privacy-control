"""Test-only node transport barriers for the live OPS crash scenarios.

The proxy forwards the real signed requests unchanged. An armed barrier can
stop selected transaction submissions before opening an upstream connection,
so a scenario can inspect the committed intent and then kill its sender.
It never fabricates a successful node response.
"""
import base64
import contextlib
import http.client
import http.server
import json
import threading
import time
import urllib.parse


class SubmissionBarrier:
    """One armed set of raw transactions, optionally forwarding the first N."""

    def __init__(self, transactions, allow):
        self.transactions = dict(transactions)  # raw transaction -> known hash
        self.allow = allow
        self.records = []
        self.waiters = []
        self.condition = threading.Condition()
        self.active = True

    def enter(self, instance, raw, context_id):
        with self.condition:
            record = {"instance": instance, "hash": self.transactions[raw], "context_id": context_id,
                      "arrived_at": time.time(), "held": self.active and self.allow == 0}
            ticket = {"record": record, "released": threading.Event(), "drop": False}
            self.records.append(record)
            if record["held"]:
                self.waiters.append(ticket)
            else:
                if self.active:
                    self.allow -= 1
                ticket["released"].set()
            self.condition.notify_all()
            return ticket

    def drop_held(self):
        """Discard already-held requests, then allow new survivor attempts.

        A killed sender's original request must never be forwarded after the
        barrier opens: that would disguise a missing survivor redelivery.
        """
        with self.condition:
            self.active = False
            for ticket in self.waiters:
                if ticket["released"].is_set():
                    continue
                ticket["drop"] = True
                ticket["record"]["discarded_at"] = time.time()
                ticket["released"].set()
            self.condition.notify_all()

    def forwarded(self, ticket, status, payload):
        with self.condition:
            if ticket["drop"] or not ticket["released"].is_set():
                raise RuntimeError("a held/discarded request must not reach the node")
            record = ticket["record"]
            record["forwarded_at"] = time.time()
            record["http_status"] = status
            result = payload.get("result") if isinstance(payload, dict) else None
            record["accepted"] = (status == 200 and isinstance(result, dict)
                                  and result.get("transaction_hash") == record["hash"]
                                  and result.get("context_id") == record["context_id"]
                                  and result.get("status") == "accepted")
            if record["accepted"]:
                record["boot_id"] = result.get("boot_id")
            self.condition.notify_all()

    def snapshot(self):
        with self.condition:
            return [dict(record) for record in self.records]

    def wait(self, predicate, timeout=30):
        """Wait on recorded transport progress, without a polling-time guess."""
        with self.condition:
            return self.condition.wait_for(lambda: predicate(self.records), timeout)


class NodeTransportBarriers:
    """One loopback HTTP proxy per OPS instance, sharing transaction barriers."""

    def __init__(self, upstream):
        target = urllib.parse.urlparse(upstream)
        if target.scheme != "http" or target.hostname not in ("localhost", "127.0.0.1"):
            raise ValueError("live barriers require an isolated loopback HTTP node")
        self.upstream = target
        self.servers, self.barriers = {}, []
        self.lock = threading.Lock()

    def arm(self, transactions, allow=0):
        if not transactions or allow < 0:
            raise ValueError("a barrier needs transactions and a non-negative allowance")
        with self.lock:
            if any(b.active for b in self.barriers):
                raise RuntimeError("finish the current transport barrier before arming another")
            barrier = SubmissionBarrier(transactions, allow)
            self.barriers.append(barrier)
            return barrier

    def enter(self, instance, request):
        if not isinstance(request, dict) or request.get("method") != "ops_submitTransaction":
            return None, None
        params = request.get("params")
        if not isinstance(params, list) or len(params) != 2 or not isinstance(params[1], str):
            return None, None
        identity = params[0]
        payload = identity.get("payload") if isinstance(identity, dict) else None
        try:
            payload = json.loads(base64.b64decode(payload, validate=True))
        except (ValueError, TypeError):
            payload = None
        # These are the real envelope's public fields; signatures and headers
        # remain untouched and are never copied to the evidence records.
        context_id = payload.get("context_id") if isinstance(payload, dict) else None
        with self.lock:
            barrier = next((b for b in reversed(self.barriers) if params[1] in b.transactions), None)
        return (barrier, barrier.enter(instance, params[1], context_id)) if barrier else (None, None)

    def endpoint(self, instance):
        if instance not in self.servers:
            owner = self

            class Handler(http.server.BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def log_message(self, *_):
                    pass

                def handle(self):
                    # SIGKILL can reset a kept-alive socket between requests,
                    # outside do_POST's expected-disconnect handling.
                    with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                        super().handle()

                def respond(self, status, data, content_type="application/json"):
                    self.send_response(status)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)

                def do_POST(self):
                    connection = None
                    try:
                        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                        try:
                            request = json.loads(body)
                        except ValueError:
                            request = None
                        barrier, ticket = owner.enter(instance, request)
                        if ticket:
                            ticket["released"].wait()
                            if ticket["drop"]:
                                self.respond(503, b'{"error":"test transport barrier discarded the stopped sender"}')
                                return
                        # No upstream connection exists until after the gate.
                        connection = http.client.HTTPConnection(owner.upstream.netloc, timeout=30)
                        headers = {k: v for k, v in self.headers.items()
                                   if k.lower() not in ("host", "connection", "content-length", "transfer-encoding")}
                        path = owner.upstream.path or "/"
                        connection.request("POST", path, body, headers)
                        response = connection.getresponse()
                        data = response.read()
                        if ticket:
                            try:
                                payload = json.loads(data)
                            except ValueError:
                                payload = None
                            barrier.forwarded(ticket, response.status, payload)
                        self.respond(response.status, data, response.getheader("Content-Type", "application/json"))
                    except (BrokenPipeError, ConnectionResetError):
                        pass  # expected when the downstream OPS process was killed
                    except Exception:
                        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                            self.respond(502, b'{"error":"test node transport failed"}')
                    finally:
                        if connection:
                            connection.close()

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.daemon_threads = True
            thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.05), daemon=True)
            thread.start()
            self.servers[instance] = (server, thread)
        return "http://127.0.0.1:" + str(self.servers[instance][0].server_port)

    def close(self):
        for barrier in self.barriers:
            barrier.drop_held()
        for server, thread in self.servers.values():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
