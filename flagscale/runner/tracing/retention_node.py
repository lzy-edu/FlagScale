# Copyright 2026 FlagOS Contributors
# SPDX-License-Identifier: Apache-2.0
"""Job-scoped recorder for one node. Only the control manifest and reports are shared."""

import argparse
import hashlib
import hmac
import http.client
import json
import os
import secrets
import shutil
import signal
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .retention import NodeEvidence


def socket_path(directory, run_id, node):
    identity = f"{Path(directory).resolve()}\0{run_id}\0{node}".encode()
    return (
        Path("/tmp")
        / ("flagscale-trace-" + str(os.getuid()) + "-" + hashlib.sha256(identity).hexdigest()[:24])
        / "events"
    )


def atomic(path, value):
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as f:
        try:
            json.dump(value, f, separators=(",", ":"))
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
            os.replace(f.name, path)
        finally:
            Path(f.name).unlink(missing_ok=True)


class Ingest(socketserver.StreamRequestHandler):
    def handle(self):
        node = self.server
        with node.condition:
            node.active += 1
        try:
            for line in iter(lambda: self.rfile.readline(1024 * 1024 + 1), b""):
                if not line.endswith(b"\n") or len(line) > 1024 * 1024:
                    raise ValueError("truncated or oversized native record")
                node.evidence.add(line)
        except (OSError, ValueError, KeyError, TypeError):
            with node.evidence.lock:
                node.evidence.loss["invalid_input_stream"] += 1
        finally:
            with node.condition:
                node.active -= 1
                node.condition.notify_all()


class NodeSocket(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    request_queue_size = 128


class Query(BaseHTTPRequestHandler):
    # A certificate pinned by the job manifest authenticates the node. A separate
    # per-node credential authenticates the monitor; no arbitrary file access.
    def log_message(self, *args):
        pass

    def do_POST(self):
        server = self.server
        if self.path != "/trace" or not hmac.compare_digest(
            self.headers.get("Authorization", ""), server.credential
        ):
            self.send_error(403)
            return
        try:
            size = int(self.headers.get("Content-Length", 0))
            if not 0 < size <= 65536:
                raise ValueError("request size")
            request = json.loads(self.rfile.read(size))
            if request["op"] == "poll":
                cursor = request["cursor"]
                if type(cursor) is not int or cursor < 0:
                    raise ValueError("cursor")
                response = server.evidence.read(cursor)
            elif request["op"] == "consumed" and server.evidence.sealed:
                server.acknowledged.set()
                response = {"consumed": True}
            elif request["op"] == "lookup":
                response = server.evidence.lookup(request["event"])
            else:
                raise ValueError("operation")
            data = json.dumps(response, separators=(",", ":")).encode()
        except (ValueError, KeyError, TypeError):
            self.send_error(400)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (OSError, ssl.SSLError):
            pass


class NodeClient:
    def __init__(self, endpoint):
        self.address = endpoint["address"]
        self.port = endpoint["port"]
        self.credential = endpoint["credential"]
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # Each freshly generated self-signed cert is trusted only for this node.
        self.context.check_hostname = False
        self.context.load_verify_locations(cadata=endpoint["certificate"])

    def request(self, **payload):
        conn = http.client.HTTPSConnection(self.address, self.port, context=self.context, timeout=3)
        try:
            conn.request(
                "POST",
                "/trace",
                json.dumps(payload),
                {"Authorization": self.credential, "Content-Type": "application/json"},
            )
            res = conn.getresponse()
            if res.status != 200:
                raise OSError(f"trace query returned HTTP {res.status}")
            return json.loads(res.read())
        finally:
            conn.close()


def serve(args):
    shared = Path(args.directory) / "retention"
    shared.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = socket_path(args.directory, args.run_id, args.node)
    path.parent.mkdir(mode=0o700)  # Exclusive ownership of this run/node endpoint.
    endpoint = shared / f"node-{args.node}.endpoint"
    ing = api = None
    finished = False
    try:
        key, cert = path.parent / "key.pem", path.parent / "cert.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "30",
                "-subj",
                "/CN=FlagScaleTraceNode",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        evidence = NodeEvidence(args.run_id, args.window_bytes)
        ing = NodeSocket(str(path), Ingest)
        ing.evidence, ing.condition, ing.active = evidence, threading.Condition(), 0
        api = ThreadingHTTPServer((args.bind, 0), Query)
        api.evidence, api.credential = evidence, secrets.token_urlsafe(32)
        api.acknowledged = threading.Event()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        api.socket = ctx.wrap_socket(api.socket, server_side=True)
        for server in (ing, api):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        atomic(
            endpoint,
            dict(
                run_id=args.run_id,
                node=args.node,
                address=args.bind,
                port=api.server_port,
                credential=api.credential,
                certificate=cert.read_text(),
            ),
        )
        terminate = threading.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: terminate.set())
        summary = shared / f"node-{args.node}.summary.json"
        final = shared / f"node-{args.node}.final.json"
        sealed = False
        seal_time = None
        frozen = None
        last_summary = 0
        previous_counts = {}
        minute_start = time.monotonic()

        def interval():
            nonlocal previous_counts, minute_start
            counts = evidence.status()["counts"]
            delta = {k: v - previous_counts.get(k, 0) for k, v in counts.items()}
            with (shared / f"node-{args.node}.intervals.jsonl").open("a") as out:
                out.write(
                    json.dumps(
                        dict(
                            end_unix_ns=time.time_ns(),
                            seconds=time.monotonic() - minute_start,
                            counts=delta,
                        )
                    )
                    + "\n"
                )
            minute_start, previous_counts = time.monotonic(), counts

        while not terminate.is_set():
            now = time.monotonic()
            if now - last_summary >= 5:
                atomic(summary, evidence.status())
                last_summary = now
            if not sealed and now - minute_start >= 60:
                interval()
            incident = shared / "incident"
            if incident.exists():
                token = incident.read_text().strip()
                if token and token != frozen:
                    snap = evidence.snapshot(True)
                    filename = "first-incident" if frozen is None else "latest-incident"
                    atomic(shared / f"node-{args.node}.{filename}.json", snap)
                    frozen = token
            if not sealed and (
                path.with_suffix(".seal").exists() or (shared / f"seal-{args.node}").exists()
            ):
                if seal_time is None:
                    # Producers have been confirmed exited by their local supervisor.
                    seal_time = now
                with ing.condition:
                    active = ing.active
                if (active == 0 and now - seal_time >= 0.5) or now - seal_time >= 10:
                    ing.shutdown()
                    with ing.condition:
                        active = ing.active
                    if active:
                        with evidence.lock:
                            evidence.loss["unclosed_producer_stream"] += active
                    stopped = (Path(args.directory) / "stop.requested").exists()
                    if stopped or evidence.loss:
                        atomic(shared / f"node-{args.node}.stop.json", evidence.snapshot(True))
                    snap = evidence.snapshot(False)
                    snap.update(run_id=args.run_id, node=args.node)
                    atomic(final, snap)
                    with evidence.lock:
                        evidence.sealed = True
                    atomic(summary, evidence.status())
                    interval()
                    sealed = True
                    seal_time = now
            if sealed and (
                api.acknowledged.is_set() or (shared / "consumed").exists() or now - seal_time > 300
            ):
                finished = True
                break
            terminate.wait(0.2)
        if not finished and not sealed:
            with evidence.lock:
                evidence.loss["collector_terminated_before_seal"] += 1
            atomic(final, dict(run_id=args.run_id, node=args.node, **evidence.snapshot(True)))
    finally:
        endpoint.unlink(missing_ok=True)
        for server in (api, ing):
            if server:
                server.server_close()
        shutil.rmtree(path.parent)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--directory", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--node", type=int, required=True)
    p.add_argument("--bind", required=True)
    p.add_argument("--window-bytes", type=int, default=32 * 1024 * 1024)
    serve(p.parse_args())


if __name__ == "__main__":
    main()
