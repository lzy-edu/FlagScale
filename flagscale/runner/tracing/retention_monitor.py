# Copyright 2026 FlagOS Contributors
# SPDX-License-Identifier: Apache-2.0
"""Stream Probe events into the standard analyzer and fetch device evidence on demand."""

import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .retention_node import NodeClient, atomic


class LiveNodes:
    enabled = True

    def __init__(self, directory, run_id, count, local_processes=0):
        self.shared = Path(directory) / "retention"
        self.run_id, self.count, self.local_processes = run_id, count, local_processes
        self.clients = {}
        self.cursor = [0] * count
        self.gaps = [0] * count
        self.statuses = {}
        self.read_errors = {}
        self.owners = {}
        self.pool = ThreadPoolExecutor(max_workers=max(1, min(count, 32)))
        self.max_read_rounds = 4
        self.last_freeze = None

    def _client(self, node):
        if node not in self.clients:
            data = json.loads((self.shared / f"node-{node}.endpoint").read_text())
            if data["run_id"] != self.run_id or data["node"] != node:
                raise ValueError("mismatched recorder identity")
            self.clients[node] = NodeClient(data)
        return self.clients[node]

    def _read(self, node):
        return self._client(node).request(op="poll", cursor=self.cursor[node])

    def poll(self):
        events = []
        active = list(range(self.count))
        for _ in range(self.max_read_rounds):
            jobs = [(n, self.pool.submit(self._read, n)) for n in active]
            active = []
            for node, job in jobs:
                try:
                    data = job.result()
                    if data["status"]["last_sequence"] < self.cursor[node]:
                        raise ValueError("recorder sequence regressed")
                    self.gaps[node] += max(0, data["first"] - self.cursor[node] - 1)
                    self.cursor[node] = data["last"]
                    status = self.statuses[node] = data["status"]
                    self.read_errors.pop(node, None)
                    for rank, pid, host in status["sources"]:
                        self.owners[(host, pid)] = node
                    events.extend(data["events"])
                    if self.cursor[node] < status["last_sequence"]:
                        active.append(node)
                except (OSError, ValueError, KeyError) as exc:
                    self.read_errors[node] = str(exc)
            if not active:
                break
        return events

    def source_issues(self):
        sources = {}
        for node, status in self.statuses.items():
            issues = []
            if self.gaps[node] or status["loss"]:
                issues.append("retention_evidence_gap")
            if node in self.read_errors or self.cursor[node] < status["last_sequence"]:
                issues.append("retention_node_behind")
            for rank, pid, _ in status["sources"]:
                sources[(rank, pid)] = tuple(issues)
        return sources

    def for_call(self, event):
        node = self.owners.get((event.get("hostname"), event.get("pid")))
        try:
            if node is None or self.gaps[node] or node in self.read_errors:
                raise ValueError("source unavailable")
            return self._client(node).request(op="lookup", event=event)
        except (OSError, KeyError, ValueError):
            return {
                "kernel_execution_status": "unknown",
                "inspector_kernel_status": "unknown",
                "inspector_correlation": "none",
                "inspector_correlation_reason": "retention_source_unavailable",
            }

    def freeze(self):
        # Keep one bounded incident window per node and coalesce an alarm burst.
        now = time.monotonic()
        if self.last_freeze is None or now - self.last_freeze >= 60:
            atomic(self.shared / "incident", time.time_ns())
            self.last_freeze = now

    def final_status(self):
        errors, finals = {}, {}
        for n in range(self.count):
            try:
                if self.statuses.get(n, {}).get("sealed"):
                    finals[n] = self.statuses[n]
                    continue
                saved = json.loads((self.shared / f"node-{n}.final.json").read_text())
                if (saved["run_id"], saved["node"]) != (self.run_id, n):
                    raise ValueError("invalid seal identity")
                finals[n] = saved["status"]
            except (OSError, KeyError, ValueError) as exc:
                errors[n] = str(exc)
        complete = len(finals) == self.count
        for n, status in finals.items():
            ranks = {r for r, _, _ in status["sources"]}
            expected = set(range(n * self.local_processes, (n + 1) * self.local_processes))
            sources = {(h, p) for _, p, h in status["sources"]}
            if (
                (self.local_processes and ranks != expected)
                or not ranks
                or sources - {tuple(x) for x in status["bridge_sources"]}
                or self.cursor[n] != status["last_sequence"]
                or status["loss"]
                or self.gaps[n]
            ):
                complete = False
        return dict(
            run_id=self.run_id,
            status="complete" if complete else "incomplete",
            scope="received_probe_stream_and_retained_device_evidence",
            missing_seals=errors,
            node_status=finals,
            probe_cursor=self.cursor,
            missed_probe_events=self.gaps,
            read_errors=self.read_errors,
        )

    def finish(self, analyzer, timeout):
        end = time.monotonic() + timeout
        while True:
            for event in self.poll():
                analyzer.ingest(
                    event, observed_monotonic_s=time.monotonic(), observed_unix_ns=time.time_ns()
                )
            result = self.final_status()
            if not result["missing_seals"] and all(
                self.cursor[n] >= s["last_sequence"] for n, s in result["node_status"].items()
            ):
                break
            if time.monotonic() >= end:
                break
            time.sleep(0.15)
        atomic(self.shared / "report.json", result)
        return result

    def acknowledge(self):
        for n in range(self.count):
            try:
                self._client(n).request(op="consumed")
            except (OSError, ValueError, KeyError):
                pass
        atomic(self.shared / "consumed", True)
        self.pool.shutdown()
