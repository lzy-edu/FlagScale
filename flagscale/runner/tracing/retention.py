# Copyright 2026 FlagOS Contributors
# SPDX-License-Identifier: Apache-2.0
"""Per-node recent evidence and independently pinned operations. No per-call files."""

import json
import threading
from collections import Counter, OrderedDict


def call_key(row):
    return (
        row.get("hostname"),
        row.get("pid"),
        row.get("profiler_process_token", row.get("process_token")),
        row.get("call_seq"),
    )


class ByteWindow:
    def __init__(self, budget):
        if budget < 1:
            raise ValueError("Empty trace window")
        self.budget = budget
        self.rows = OrderedDict()
        self.size = 0
        self.end = 0

    def append(self, raw, on_evict=None):
        self.end += 1
        self.rows[self.end] = raw
        self.size += len(raw)
        while self.size > self.budget:
            _, old = self.rows.popitem(last=False)
            self.size -= len(old)
            if on_evict:
                on_evict(old)

    def after(self, cursor, limit):
        first = next(iter(self.rows), self.end + 1)
        start = max(first, cursor + 1)
        size, records = 0, []
        for seq in range(start, self.end + 1):
            raw = self.rows[seq]
            records.append(raw)
            size += len(raw)
            if size >= limit:
                break
        return first, start + len(records) - 1, records


def valid_channels(row):
    expected, channels = row.get("expected_channels"), row.get("channels")
    if type(expected) is not int or expected <= 0 or not isinstance(channels, list):
        return False
    seen = set()
    for item in channels:
        if not isinstance(item, dict):
            return False
        ch, begin, end = (item.get(k) for k in ("channel_id", "begin", "end"))
        if not all(type(x) is int for x in (ch, begin, end)):
            return False
        if ch < 0 or ch in seen or not 0 < begin <= end:
            return False
        seen.add(ch)
    return len(seen) == expected and row.get("invalid") is False


class NodeEvidence:
    def __init__(self, run_id, budget):
        self.run_id = run_id
        self.lock = threading.RLock()
        self.probe = ByteWindow(budget)
        self.bridge = ByteWindow(budget)
        self.pin_budget = budget
        self.pins = {}
        self.pin_bytes = 0
        self.enter_rows = {}
        self.device_calls = Counter()
        self.known = set()
        self.bridged = set()
        self.bridge_errors = set()
        self.bridge_index = {}
        self.sealed = False
        self.forgotten = {}
        self.counts = Counter()
        self.loss = Counter()

    def _pin(self, key, raw):
        old = self.pins.get(key, b"")
        if self.pin_bytes + len(raw) - len(old) > self.pin_budget:
            self.loss["pending_capacity_exceeded"] += 1
            return
        self.pin_bytes += len(raw) - len(old)
        self.pins[key] = raw

    def _release(self, key):
        self.pin_bytes -= len(self.pins.pop(key, b""))

    def _evicted_probe(self, raw):
        event = json.loads(raw)
        if event.get("event") == "nccl_call" and event.get("phase") == "enter":
            key = call_key(event)
            if self.enter_rows.get(key) is raw:
                self.enter_rows.pop(key)

    def _evicted_bridge(self, raw):
        key = call_key(json.loads(raw))
        group = self.bridge_index.get(key)
        if group:
            group.popitem(last=False)
            if not group:
                self.bridge_index.pop(key)
        if type(key[-1]) is int:
            self.forgotten[key[:3]] = max(key[-1], self.forgotten.get(key[:3], -1))

    def add(self, raw):
        row = json.loads(raw)
        if not isinstance(row, dict):
            raise ValueError("Trace record must be an object")
        with self.lock:
            kind = row.get("record_type")
            if kind == "flagscale_profiler_v5_v1":
                key = ("device", *call_key(row), row["task_id"])
                self.bridged.add((row["hostname"], row["pid"]))
                self.bridge_index.setdefault(call_key(row), OrderedDict())[self.bridge.end + 1] = (
                    raw
                )
                self.bridge.append(raw, self._evicted_bridge)
                self.counts["device_records"] += 1
                call = call_key(row)
                previous = self.pins.get(key)
                if previous is not None:
                    earlier = json.loads(previous)
                    fields = (
                        "expected_channels",
                        "comm_id",
                        "api",
                        "count",
                        "datatype",
                        "rank",
                        "nranks",
                        "peer",
                    )
                    old = {v["channel_id"]: v for v in earlier["channels"]}
                    new = {v["channel_id"]: v for v in row["channels"]}
                    conflict = (
                        earlier["revision"] > row["revision"]
                        or (earlier["revision"] == row["revision"] and earlier != row)
                        or any(earlier.get(k) != row.get(k) for k in fields)
                        or any(
                            k not in new
                            or a["begin"] != new[k]["begin"]
                            or (a["end"] and a["end"] != new[k]["end"])
                            for k, a in old.items()
                        )
                    )
                    if conflict:
                        self.loss["device_revision_conflict"] += 1
                        self._pin(("conflict", *key[1:]), raw)
                        return
                if valid_channels(row):
                    if previous is not None:
                        self.device_calls[call] -= 1
                        if not self.device_calls[call]:
                            del self.device_calls[call]
                            self._release(("api_for_device", *call))
                    self._release(key)
                    self.counts["device_complete_records"] += 1
                else:
                    self._pin(key, raw)
                    if previous is None and key in self.pins:
                        self.device_calls[call] += 1
                        if call in self.enter_rows:
                            self._pin(("api_for_device", *call), self.enter_rows[call])
            elif kind == "flagscale_bridge_error_v1":
                self.bridge_errors.add((row.get("hostname"), row.get("pid")))
                self.loss["bridge_error"] += 1
            elif kind == "flagscale_bridge_lifecycle_v1":
                self.counts["contexts_finalized"] += 1
            elif row.get("run_id") == self.run_id and "event" in row:
                self.probe.append(raw, self._evicted_probe)
                event = row["event"]
                if event == "process_start":
                    self.known.add((row["rank"], row["pid"], row["hostname"]))
                elif event == "nccl_call":
                    phase = row.get("phase")
                    key = ("cpu", *call_key(row))
                    if phase == "enter":
                        call = call_key(row)
                        if len(raw) <= self.probe.budget:
                            self.enter_rows[call] = raw
                        self._pin(key, raw)
                        if self.device_calls.get(call):
                            self._pin(("api_for_device", *call), raw)
                        self.counts["api_enter"] += 1
                    elif phase == "exit":
                        previous = self.pins.get(key)
                        if previous:
                            begin = json.loads(previous).get("timestamp_mono_ns")
                            end = row.get("timestamp_mono_ns")
                            if type(begin) is int and type(end) is int and end >= begin:
                                self.counts["cpu_api_elapsed_ns"] += end - begin
                                self.counts["timed_api_exits"] += 1
                        self._release(key)
                        self.counts["api_exit"] += 1
                elif event == "probe_status":
                    for name in ("dropped_events", "write_errors", "sync_errors"):
                        if row.get(name, 0):
                            self.loss[name] = max(self.loss[name], row[name])
            else:
                raise ValueError("Unexpected run or record type")

    def status(self):
        with self.lock:
            return dict(
                counts=dict(self.counts),
                loss=dict(self.loss),
                sealed=self.sealed,
                probe_bytes=self.probe.size,
                bridge_bytes=self.bridge.size,
                pin_bytes=self.pin_bytes,
                byte_budget=self.probe.budget,
                pending=len(self.pins),
                last_sequence=self.probe.end,
                sources=sorted(self.known),
                bridge_sources=sorted(self.bridged),
            )

    def read(self, cursor, limit=2 * 1024 * 1024):
        with self.lock:
            first, last, rows = self.probe.after(cursor, limit)
            return dict(
                first=first, last=last, events=[json.loads(r) for r in rows], status=self.status()
            )

    def lookup(self, event):
        from .profiler_bridge import bridge_evidence

        key = call_key(event)
        with self.lock:
            if self.loss or (key[0], key[1]) in self.bridge_errors:
                reason = "node_collection_incomplete"
            elif self.forgotten.get(key[:3], -1) >= key[-1]:
                reason = "device_history_outside_window"
            else:
                rows = list(self.bridge_index.get(key, {}).values())
                reason = None
        if reason:
            with self.lock:
                pinned = [
                    json.loads(raw)
                    for k, raw in self.pins.items()
                    if k[0] == "device" and k[1:5] == key
                ]
            return {
                "inspector_correlation": "none",
                "kernel_execution_status": "unknown",
                "retained_device_progress": pinned,
                "inspector_kernel_status": "unknown",
                "inspector_correlation_reason": reason,
            }
        return bridge_evidence(event, tuple(json.loads(raw) for raw in rows))

    def snapshot(self, include_recent):
        with self.lock:
            return dict(
                status=self.status(),
                pending=[json.loads(v) for v in self.pins.values()],
                recent_probe=[json.loads(v) for v in self.probe.rows.values()]
                if include_recent
                else [],
                recent_bridge=[json.loads(v) for v in self.bridge.rows.values()]
                if include_recent
                else [],
            )
