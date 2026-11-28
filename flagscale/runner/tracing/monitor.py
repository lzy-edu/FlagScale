# Copyright 2026 FlagOS Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Low-priority CPU process that tails NCCL probe JSONL files."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import time
from pathlib import Path
from typing import TextIO

from .analyzer import Finding, TraceAnalyzer
from .inspector import InspectorReader
from flagscale.runner.heartbeat.health_reader import HardwareHealthReader

logger = logging.getLogger("flagscale.tracing")

_TRACE_SOURCE_PATTERN = re.compile(r"^rank_(\d+)_pid_(\d+)\.jsonl$")


class JsonlTailer:
    """Incrementally read complete JSON lines from per-process trace files."""

    def __init__(self, trace_dir: Path) -> None:
        self.trace_dir = trace_dir
        self._offsets: dict[Path, int] = {}
        self._remainders: dict[Path, str] = {}
        self.read_errors: dict[str, dict] = {}
        self._source_paths: dict[tuple[int, int], Path] = {}
        self._source_issues: dict[tuple[int, int], set[str]] = {}

    @staticmethod
    def _source_key(path: Path) -> tuple[int, int] | None:
        match = _TRACE_SOURCE_PATTERN.fullmatch(path.name)
        if match is None:
            return None
        return int(match.group(1)), int(match.group(2))

    def source_issues(self) -> dict[tuple[int, int], tuple[str, ...]]:
        """Return collector-visible source files and permanent/transient issues."""

        return {
            source: tuple(sorted(self._source_issues.get(source, set())))
            for source in self._source_paths
        }

    def poll(self) -> list[dict]:
        events: list[dict] = []
        paths = sorted(self.trace_dir.glob("rank_*_pid_*.jsonl"))
        visible_paths = set(paths)
        for source, path in self._source_paths.items():
            if path not in visible_paths:
                self._source_issues.setdefault(source, set()).add("trace_file_missing")

        for path in paths:
            source = self._source_key(path)
            if source is not None:
                self._source_paths[source] = path
                issues = self._source_issues.setdefault(source, set())
                issues.discard("trace_file_missing")
                issues.discard("trace_read_error")
            offset = self._offsets.get(path, 0)
            try:
                size = path.stat().st_size
                if size < offset:
                    offset = 0
                    self._remainders.pop(path, None)
                    if source is not None:
                        issues.add("trace_file_truncated")
                with path.open("r", encoding="utf-8", errors="replace") as file_obj:
                    file_obj.seek(offset)
                    chunk = file_obj.read()
                    self._offsets[path] = file_obj.tell()
            except OSError as exc:
                self.read_errors[str(path)] = {
                    "path": str(path),
                    "error_type": type(exc).__name__,
                    "errno": exc.errno,
                    "error": str(exc),
                }
                logger.debug("Could not read %s: %s", path, exc)
                if source is not None:
                    issues.add("trace_read_error")
                continue
            self.read_errors.pop(str(path), None)

            if not chunk:
                continue
            text = self._remainders.pop(path, "") + chunk
            lines = text.splitlines(keepends=True)
            for line in lines:
                if not line.endswith(("\n", "\r")):
                    self._remainders[path] = line
                    if source is not None:
                        issues.add("partial_json_record")
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("Ignored malformed trace line in %s", path)
                    if source is not None:
                        issues.add("malformed_json_record")
                    continue
                if isinstance(event, dict):
                    events.append(event)
            if source is not None and path not in self._remainders:
                issues.discard("partial_json_record")
        return events


def _append_findings(file_obj: TextIO, findings: list[Finding]) -> None:
    for finding in findings:
        payload = json.dumps(finding.to_dict(), sort_keys=True, separators=(",", ":"))
        file_obj.write(payload + "\n")
        logger.warning("NCCL trace finding: %s", payload)
    if findings:
        file_obj.flush()
        os.fsync(file_obj.fileno())


def _completion_exit_code(path: Path | None) -> int | None:
    if path is None or not path.exists():
        return None
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _drain_forensics(
    trace_dir,
    run_id,
    tailers,
    reader,
    analyzer,
    reason,
    timeout_s=2.0,
    expected_nodes=0,
    shutdown_timeout_s=30.0,
    peer_hosts=(),
    ssh_port=22,
):
    """Bound scheduling time; the stop supervisor also caps a blocked I/O process."""
    started = time.monotonic()
    journal = trace_dir / "monitor.shutdown.jsonl"

    def append(record):
        with journal.open("a", encoding="utf-8") as output:
            output.write(json.dumps({"run_id": run_id, **record}) + "\n")
            output.flush()
            os.fsync(output.fileno())

    append(
        {
            "event": "drain_started",
            "reason": reason,
            "timestamp_unix_ns": time.time_ns(),
            "budget_s": timeout_s,
        }
    )
    final = None
    if expected_nodes:
        from .shutdown import finish_online

        final = finish_online(
            trace_dir,
            run_id,
            expected_nodes,
            reader.directory if reader.enabled else None,
            shutdown_timeout_s,
            peer_hosts=peer_hosts,
            ssh_port=ssh_port,
        )
    polls = 0
    while time.monotonic() - started < timeout_s:
        for tailer in tailers:
            for event in tailer.poll():
                analyzer.ingest(
                    event, observed_monotonic_s=time.monotonic(), observed_unix_ns=time.time_ns()
                )
        reader.poll()
        polls += 1
        remaining = timeout_s - (time.monotonic() - started)
        if remaining > 0:
            time.sleep(min(0.1, remaining))
    try:
        inventory = reader._store.incomplete_inventory() if reader._store is not None else {}
    except Exception as exc:
        inventory = {"error_type": type(exc).__name__, "error": str(exc), "available": False}
    if final is not None and final.get("status") == "files_verified":
        inventory = final["audit"].get("incomplete_inventory", {})
    summary = {
        "event": "drain_finished",
        "reason": reason,
        "timestamp_unix_ns": time.time_ns(),
        "elapsed_s": time.monotonic() - started,
        "polls": polls,
        "inspector": reader.diagnostics,
        "incomplete_inventory": inventory,
        "probe_read_errors": [e for tailer in tailers for e in tailer.read_errors.values()],
        "probe_partial_lines": sum(len(tailer._remainders) for tailer in tailers),
        "scope": "sealed_producer_files"
        if final and final.get("status") == "files_verified"
        else "observed_files_only_not_proof_all_producers_finished",
        "final_evidence": final,
    }
    append(summary)
    return summary


def run_monitor(args: argparse.Namespace) -> int:
    trace_dir = Path(args.trace_dir)
    trace_dir.mkdir(parents=True, exist_ok=True)
    report_file = Path(args.report_file)
    report_file.parent.mkdir(parents=True, exist_ok=True)
    completion_file = Path(args.completion_file) if args.completion_file else None

    if args.nice:
        try:
            os.nice(args.nice)
        except (AttributeError, OSError):
            logger.debug("Could not adjust analyzer niceness", exc_info=True)

    analyzer = TraceAnalyzer(
        run_id=args.run_id,
        heartbeat_timeout_s=args.heartbeat_timeout,
        collective_timeout_s=args.collective_timeout,
        delayed_enter_threshold_s=args.delayed_enter_threshold,
        checkpoint_timeout_s=args.checkpoint_timeout,
        p2p_timeout_s=args.p2p_timeout,
        p2p_match_window_s=args.p2p_match_window,
        missing_exit_timeout_s=args.missing_exit_timeout,
    )
    trace_tailer = JsonlTailer(trace_dir)
    tailers = [trace_tailer]
    if args.heartbeat_dir:
        tailers.append(JsonlTailer(Path(args.heartbeat_dir)))
    hardware_reader = HardwareHealthReader(
        Path(args.heartbeat_dir) if args.heartbeat_dir else trace_dir,
        args.run_id,
        args.hardware_health,
        args.hardware_health_stale_after,
    )
    inspector_reader = InspectorReader(
        Path(args.inspector_dir) if args.inspector_dir else trace_dir / "inspector",
        enabled=bool(args.inspector_dir),
        correlation_window_s=args.inspector_correlation_window,
    )
    stopping = False
    stop_reason = "signal"
    failed_completion_seen_monotonic_s: float | None = None

    def request_stop(_signum, _frame) -> None:
        nonlocal stopping
        stopping = True

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, request_stop)

    with report_file.open("a", encoding="utf-8") as output:
        while not stopping:
            observed_monotonic_s = time.monotonic()
            observed_unix_ns = time.time_ns()
            for tailer in tailers:
                for event in tailer.poll():
                    analyzer.ingest(
                        event,
                        observed_monotonic_s=observed_monotonic_s,
                        observed_unix_ns=observed_unix_ns,
                    )

            scan_unix_ns = time.time_ns()
            hardware_health, _hardware_findings = hardware_reader.poll(scan_unix_ns)
            inspector = inspector_reader.poll()
            findings = analyzer.scan(
                now_monotonic_s=time.monotonic(),
                now_unix_ns=scan_unix_ns,
                hardware_health=hardware_health,
                inspector=inspector,
                trace_source_issues=trace_tailer.source_issues(),
            )
            if not stopping and not (trace_dir / "stop.requested").exists():
                _append_findings(output, findings)

            exit_code = _completion_exit_code(completion_file)
            if exit_code is not None and exit_code != 0:
                if failed_completion_seen_monotonic_s is None:
                    failed_completion_seen_monotonic_s = time.monotonic()
                    logger.info(
                        "Training exited with code %s; keeping analyzer alive for %.1fs",
                        exit_code,
                        args.failure_grace_period,
                    )

            failure_grace_elapsed = (
                failed_completion_seen_monotonic_s is not None
                and time.monotonic() - failed_completion_seen_monotonic_s
                >= args.failure_grace_period
            )
            all_nodes_sealed = False
            if getattr(args, "expected_nodes", 0):
                from .shutdown import load_seals

                seals, missing_nodes, _ = load_seals(trace_dir, args.run_id, args.expected_nodes)
                all_nodes_sealed = not missing_nodes and (
                    (trace_dir / "stop.requested").exists()
                    or all(s.get("training", {}).get("training_exit_code") == 0 for s in seals)
                )
            if exit_code == 0 or failure_grace_elapsed or all_nodes_sealed:
                # One last poll prevents losing lines appended immediately before the
                # training shell wrote its completion marker. A failed run stays alive
                # for a bounded grace period so timeout-based crash evidence can mature.
                for tailer in tailers:
                    for event in tailer.poll():
                        analyzer.ingest(
                            event,
                            observed_monotonic_s=time.monotonic(),
                            observed_unix_ns=time.time_ns(),
                        )
                final_unix_ns = time.time_ns()
                final_hardware_health, _hardware_findings = hardware_reader.poll(final_unix_ns)
                final_findings = analyzer.scan(
                    now_monotonic_s=time.monotonic(),
                    now_unix_ns=final_unix_ns,
                    hardware_health=final_hardware_health,
                    inspector=inspector_reader.poll(),
                    trace_source_issues=trace_tailer.source_issues(),
                )
                if not stopping and not (trace_dir / "stop.requested").exists():
                    _append_findings(output, final_findings)
                stop_reason = "training_complete" if exit_code == 0 else "failure_grace_elapsed"
                break
            time.sleep(args.scan_interval)
        _drain_forensics(
            trace_dir,
            args.run_id,
            tailers,
            inspector_reader,
            analyzer,
            stop_reason,
            timeout_s=getattr(args, "drain_timeout", 2.0),
            expected_nodes=getattr(args, "expected_nodes", 0),
            shutdown_timeout_s=getattr(args, "shutdown_timeout", 30.0),
            peer_hosts=json.loads(getattr(args, "peer_hosts", "[]")),
            ssh_port=getattr(args, "ssh_port", 22),
        )
        if not stopping and not (trace_dir / "stop.requested").exists():
            final_unix_ns = time.time_ns()
            final_health, _ = hardware_reader.poll(final_unix_ns)
            _append_findings(
                output,
                analyzer.scan(
                    now_monotonic_s=time.monotonic(),
                    now_unix_ns=final_unix_ns,
                    hardware_health=final_health,
                    inspector=inspector_reader.poll(),
                    trace_source_issues=trace_tailer.source_issues(),
                ),
            )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace-dir", required=True)
    parser.add_argument("--heartbeat-dir")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--heartbeat-timeout", type=float, default=30.0)
    parser.add_argument("--collective-timeout", type=float, default=60.0)
    parser.add_argument("--delayed-enter-threshold", type=float, default=30.0)
    parser.add_argument("--checkpoint-timeout", type=float, default=1800.0)
    parser.add_argument("--p2p-timeout", type=float, default=60.0)
    parser.add_argument("--p2p-match-window", type=float, default=30.0)
    parser.add_argument("--missing-exit-timeout", type=float, default=60.0)
    parser.add_argument("--failure-grace-period", type=float, default=60.0)
    parser.add_argument("--scan-interval", type=float, default=1.0)
    parser.add_argument("--completion-file")
    parser.add_argument("--report-file", required=True)
    parser.add_argument("--nice", type=int, default=10)
    parser.add_argument("--hardware-health", action="store_true")
    parser.add_argument("--hardware-health-stale-after", type=float, default=180.0)
    parser.add_argument("--inspector-dir")
    parser.add_argument("--inspector-correlation-window", type=float, default=5.0)
    parser.add_argument("--drain-timeout", type=float, default=2.0)
    parser.add_argument("--expected-nodes", type=int, default=0)
    parser.add_argument("--peer-hosts", default="[]")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--shutdown-timeout", type=float, default=30.0)
    return parser


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args = build_parser().parse_args()
    for name in (
        "heartbeat_timeout",
        "collective_timeout",
        "delayed_enter_threshold",
        "checkpoint_timeout",
        "p2p_timeout",
        "p2p_match_window",
        "missing_exit_timeout",
        "failure_grace_period",
        "scan_interval",
        "hardware_health_stale_after",
        "inspector_correlation_window",
        "drain_timeout",
    ):
        if getattr(args, name) <= 0:
            raise SystemExit(f"--{name.replace('_', '-')} must be greater than zero")
    if args.p2p_match_window > args.p2p_timeout:
        raise SystemExit("--p2p-match-window must not exceed --p2p-timeout")
    return run_monitor(args)


if __name__ == "__main__":
    raise SystemExit(main())
