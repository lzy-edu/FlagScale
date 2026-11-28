# Copyright 2026 FlagOS Contributors
# SPDX-License-Identifier: Apache-2.0
"""Independent post-stop evidence audit. Never changes online findings or stop results."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

SCRIPT = Path(__file__).resolve()
MAX_LINE = 8 * 1024 * 1024
MAX_BYTES = 2 * 1024 * 1024 * 1024


def write_json(path, value):
    path = Path(path)
    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def error_record(exc, **context):
    return {
        **context,
        "error_type": type(exc).__name__,
        "errno": getattr(exc, "errno", None),
        "error": str(exc),
    }


def fingerprint(path, destination=None):
    """Hash a bounded, stable snapshot; size alone cannot identify file contents."""
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        before = os.fstat(stream.fileno())
        if before.st_size > MAX_BYTES:
            raise ValueError("file_size_budget_exceeded")
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_BYTES:
                raise ValueError("file_size_budget_exceeded")
            digest.update(chunk)
            if destination is not None:
                destination.write(chunk)
        after = os.fstat(stream.fileno())
    with Path(path).open("rb") as current_stream:
        current = os.fstat(current_stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if (
        identity(before) != identity(after)
        or identity(after) != identity(current)
        or size != after.st_size
    ):
        raise ValueError("file_changed_during_snapshot")
    return {"size": size, "sha256": digest.hexdigest()}


def process_status(node, *, allow_wrapper=False):
    # Import Linux ownership code only in the node-local collector.
    from flagscale.runner.training_process import _alive, _owned

    state = read_json(node["state_file"])
    if not node.get("token") or state.get("token") != node["token"]:
        raise ValueError("training_identity_changed_or_missing")
    if state.get("hostname") != socket.gethostname():
        raise ValueError("training_state_wrong_host")
    if state.get("boot_id") != Path("/proc/sys/kernel/random/boot_id").read_text().strip():
        raise ValueError("training_state_wrong_boot")
    alive = _owned(state["token"])
    keys = ("launcher", "supervisor") if allow_wrapper else ("launcher", "supervisor", "wrapper")
    alive.extend(i for key in keys if (i := state.get(key)) and _alive(i))
    if alive or state.get("status") != "exited":
        raise ValueError("training_exit_unconfirmed")
    return {
        "confirmed_exited": True,
        "token": state["token"],
        "training_exit_code": state.get("training_exit_code"),
    }


def collect_node(request, node, *, allow_wrapper=False, sync_files=False):
    """Run on the producer node after stopping; publish existing bytes, not GPU success."""
    result = {
        "request_id": request["request_id"],
        "run_id": request["run_id"],
        "node_rank": node["node_rank"],
        "hostname": socket.gethostname(),
        "files": [],
        "producers": [],
        "errors": [],
    }
    try:
        result["training"] = (
            process_status(node, allow_wrapper=True) if allow_wrapper else process_status(node)
        )
    except Exception as exc:
        result["errors"].append(error_record(exc, stage="training_identity"))
        return result
    trace = Path(request["trace_dir"])
    inspector = Path(request["inspector_dir"]) if request.get("inspector_dir") else None
    candidates = []
    for path in sorted(trace.glob("rank_*_pid_*.jsonl")):
        try:
            with path.open("rb") as stream:
                first = json.loads(stream.readline(MAX_LINE + 1))
            if first.get("hostname") != result["hostname"]:
                continue
            if first.get("run_id") != request["run_id"] or first.get("event") != "process_start":
                raise ValueError("probe_run_identity_invalid")
            producer = {k: first[k] for k in ("hostname", "pid", "rank", "local_rank")}
            result["producers"].append(producer)
            candidates.append(("probe", path))
            if inspector is not None:
                host, pid = producer["hostname"], producer["pid"]
                candidates.append(("inspector", inspector / f"{host}-pid{pid}.log"))
                if request.get("bridge_enabled"):
                    candidates.append(("inspector", inspector / f"bridge-{host}-{pid}.jsonl"))
        except Exception as exc:
            record = error_record(exc, stage="producer_discovery", path=str(path))
            if allow_wrapper:
                # Another node may still be writing. The global consumer must
                # later find this exact path in its owning node's verified seal.
                result.setdefault("unclassified_files", []).append(record)
            else:
                result["errors"].append(record)
    local_ranks = [p["local_rank"] for p in result["producers"]]
    if not node.get("nproc") or sorted(local_ranks) != list(range(node["nproc"])):
        result["errors"].append(
            {
                "stage": "producer_discovery",
                "error": "expected_local_ranks_not_observed",
                "observed": local_ranks,
                "expected": node.get("nproc"),
            }
        )
    total = 0
    for kind, path in candidates:
        try:
            if sync_files:
                with path.open("rb") as stream:
                    os.fsync(stream.fileno())
            total += path.stat().st_size
            if total > MAX_BYTES or len(candidates) > 8192:
                raise ValueError("manifest_budget_exceeded")
            result["files"].append({"kind": kind, "path": str(path), **fingerprint(path)})
        except Exception as exc:
            result["errors"].append(error_record(exc, stage="file_snapshot", path=str(path)))
    result["finished_unix_ns"] = time.time_ns()
    return result


def copy_verified(entry, request, directory, deadline):
    path = Path(entry["path"])
    root = Path(request["trace_dir"] if entry["kind"] == "probe" else request["inspector_dir"])
    if path.is_symlink() or path.resolve().parent != root.resolve():
        raise ValueError("file_outside_run_directory")
    target = directory / entry["kind"] / path.name
    target.parent.mkdir(exist_ok=True)
    while True:
        try:
            with target.open("wb") as output:
                actual = fingerprint(path, output)
            if actual != {k: entry[k] for k in ("size", "sha256")}:
                raise ValueError("producer_consumer_content_mismatch")
            return target
        except (OSError, ValueError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


def parse_probe(path, run_id):
    with path.open("rb") as stream:
        while line := stream.readline(MAX_LINE + 1):
            if len(line) > MAX_LINE or not line.endswith(b"\n"):
                raise ValueError("probe_partial_or_oversize_record")
            event = json.loads(line)
            if not isinstance(event, dict) or event.get("run_id") != run_id:
                raise ValueError("probe_record_wrong_run")
            yield event


def audit_snapshots(request, manifests, directory, deadline=None, progress=None):
    from flagscale.runner.tracing.inspector import InspectorReader

    errors = []
    copied = []
    total = 0
    for manifest in manifests:
        for entry in manifest.get("files", []):
            try:
                if progress:
                    progress(
                        "verifying_file", file=Path(entry["path"]).name, verified_files=len(copied)
                    )
                total += entry["size"]
                if total > MAX_BYTES:
                    raise ValueError("snapshot_total_budget_exceeded")
                # Bound retries for unavailable content. A successful copy/hash
                # may take longer, and is independent of the overall audit size.
                retry_until = deadline if deadline is not None else time.monotonic() + 15
                copied.append(copy_verified(entry, request, directory, retry_until))
            except Exception as exc:
                errors.append(error_record(exc, stage="content_verification", path=entry["path"]))
    reader = InspectorReader(directory / "inspector", enabled=bool(request.get("inspector_dir")))
    if progress:
        progress("reading_inspector", verified_files=len(copied))
    last_update = time.monotonic()
    index = reader.poll()
    while (
        request.get("inspector_dir")
        and not index.caught_up
        and not index.errors
        and (deadline is None or time.monotonic() < deadline)
    ):
        index = reader.poll()
        if progress and time.monotonic() - last_update >= 5:
            progress(
                "reading_inspector",
                verified_files=len(copied),
                bytes_read=reader.diagnostics["read_bytes"],
            )
            last_update = time.monotonic()
    if request.get("inspector_dir") and not index.caught_up:
        errors.append(
            {"stage": "inspector_parse", "error": "not_fully_parsed", "details": reader.diagnostics}
        )
    counts = collections.Counter()
    examples = []
    online = []
    shutdown = Path(request["trace_dir"]) / "monitor.shutdown.jsonl"
    if shutdown.exists():
        try:
            for line in shutdown.read_text().splitlines():
                row = json.loads(line)
                if row.get("run_id") != request["run_id"]:
                    raise ValueError("online_report_wrong_run")
                if row.get("event") == "drain_finished":
                    online = row.get("incomplete_inventory", {}).get("records", [])
        except (OSError, ValueError) as exc:
            errors.append(error_record(exc, stage="online_report"))
    online_keys = {
        (r.get("hostname"), r.get("pid"), r.get("process_token"), r.get("call_seq")) for r in online
    }
    resolutions = []
    for path in copied:
        if path.parent.name != "probe":
            continue
        if progress:
            progress("matching_probe_calls", file=path.name, verified_files=len(copied))
        last_update = time.monotonic()
        try:
            for lines_read, event in enumerate(parse_probe(path, request["run_id"]), 1):
                now = time.monotonic()
                if deadline is not None and now >= deadline:
                    raise TimeoutError("final_audit_deadline")
                if progress and lines_read % 1000 == 0 and now - last_update >= 5:
                    progress(
                        "matching_probe_calls",
                        file=path.name,
                        verified_files=len(copied),
                        lines_read=lines_read,
                    )
                    last_update = now
                if (
                    event.get("event") != "nccl_call"
                    or event.get("phase") != "enter"
                    or event.get("api") in {"ncclGroupStart", "ncclGroupEnd"}
                ):
                    continue
                evidence = index.for_call(event)
                status = evidence["kernel_execution_status"]
                counts[
                    (event.get("comm_nranks"), status, evidence.get("inspector_correlation_reason"))
                ] += 1
                item = {
                    "hostname": event.get("hostname"),
                    "pid": event.get("pid"),
                    "call_seq": event.get("call_seq"),
                    "rank": event.get("rank"),
                    "status": status,
                    "reason": evidence.get("inspector_correlation_reason"),
                }
                if (
                    status != "completed"
                    and event.get("comm_nranks", 0) > 1
                    and len(examples) < 256
                ):
                    examples.append(item)
                key = (
                    event.get("hostname"),
                    event.get("pid"),
                    event.get("profiler_process_token"),
                    event.get("call_seq"),
                )
                if key in online_keys:
                    resolutions.append(item)
        except (OSError, ValueError, TimeoutError) as exc:
            errors.append(error_record(exc, stage="probe_parse", path=path.name))
    result = {
        "errors": errors,
        "verified_files": len(copied),
        "verified_bytes": total,
        "call_counts": [
            {"nranks": n, "status": s, "reason": why, "count": count}
            for (n, s, why), count in counts.items()
        ],
        "noncomplete_examples": examples,
        "example_limit": 256,
        "online_incomplete_records_observed": len(online),
        "online_call_resolutions": resolutions,
        "inspector": reader.diagnostics,
        "incomplete_inventory": reader._store.incomplete_inventory()
        if reader._store is not None
        else {},
    }
    if reader._store is not None:
        reader._store._cleanup()
    return result


def run_audit(request, output):
    started = time.monotonic()
    budget = request.get("budget_s")
    deadline = started + budget if budget is not None else None
    report = {
        "run_id": request["run_id"],
        "request_id": request["request_id"],
        "status": "running",
        "scope": "registered_producer_files_not_proof_all_device_callbacks_emitted",
        "nodes": [],
        "errors": [],
    }

    def progress(stage, **details):
        report["progress"] = {"stage": stage, "updated_unix_ns": time.time_ns(), **details}
        write_json(output, report)
        context = " ".join(f"{key}={value}" for key, value in details.items())
        print(f"FlagScale final evidence audit: {stage} {context}".rstrip(), flush=True)

    progress("starting")
    for node in request["nodes"]:
        progress(
            "waiting_for_node", node_rank=node["node_rank"], nodes_collected=len(report["nodes"])
        )
        try:
            command = [
                sys.executable,
                str(SCRIPT),
                "collect",
                "--request",
                request["request_file"],
                "--node",
                str(node["node_rank"]),
            ]
            if node["host"] != "localhost":
                command = [
                    "ssh",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=5",
                    "-o",
                    "ServerAliveInterval=5",
                    "-o",
                    "ServerAliveCountMax=3",
                    "-p",
                    str(request["ssh_port"]),
                    node["host"],
                    shlex.join(command),
                ]
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=(
                    max(0.1, min(15, deadline - time.monotonic())) if deadline is not None else None
                ),
                check=True,
            )
            manifest = json.loads(result.stdout)
            if (manifest.get("run_id"), manifest.get("request_id"), manifest.get("node_rank")) != (
                request["run_id"],
                request["request_id"],
                node["node_rank"],
            ):
                raise ValueError("manifest_identity_mismatch")
            report["nodes"].append(manifest)
        except Exception as exc:
            report["errors"].append(
                error_record(exc, stage="node_collection", node_rank=node["node_rank"])
            )
        write_json(output, report)
    with tempfile.TemporaryDirectory(
        prefix="flagscale-final-evidence-", dir="/tmp" if Path("/tmp").exists() else None
    ) as tmp:
        report["audit"] = audit_snapshots(request, report["nodes"], Path(tmp), deadline, progress)
    ranks = [p["rank"] for m in report["nodes"] for p in m["producers"]]
    expected = sum(n.get("nproc") or 0 for n in request["nodes"])
    if sorted(ranks) != list(range(expected)) or not expected:
        report["errors"].append(
            {
                "stage": "producer_coverage",
                "error": "expected_global_ranks_not_observed",
                "observed": ranks,
                "expected": expected,
            }
        )
    complete = (
        len(report["nodes"]) == len(request["nodes"])
        and not report["errors"]
        and not report["audit"]["errors"]
        and all(not n["errors"] for n in report["nodes"])
    )
    report.update(
        status="files_verified" if complete else "incomplete",
        elapsed_s=time.monotonic() - started,
        finished_unix_ns=time.time_ns(),
    )
    progress("finished", status=report["status"])


def supervise(request_file):
    request = read_json(request_file)
    output = Path(request_file).with_name("report.json")
    try:
        subprocess.run(
            [sys.executable, str(SCRIPT), "audit", "--request", str(request_file)],
            check=True,
            timeout=request.get("budget_s"),
        )
    except Exception as exc:
        try:
            report = read_json(output)
        except (OSError, ValueError):
            report = {"run_id": request["run_id"], "request_id": request["request_id"]}
        report.update(
            status="timeout" if isinstance(exc, subprocess.TimeoutExpired) else "failed",
            supervisor_error=error_record(exc),
            finished_unix_ns=time.time_ns(),
        )
        write_json(output, report)


def start_final_audit(trace, nodes, ssh_port=22, budget_s=None):
    """Detach from training stop. Its result never replaces the stop return code."""
    request_id = uuid.uuid4().hex
    directory = Path(trace.trace_dir) / "final_evidence" / request_id
    directory.mkdir(parents=True)
    request_file = directory / "request.json"
    request = {
        "request_id": request_id,
        "run_id": trace.run_id,
        "trace_dir": trace.trace_dir,
        "inspector_dir": trace.inspector_dump_dir if trace.inspector_enabled else "",
        "bridge_enabled": bool(trace.inspector_bridge_library),
        "ssh_port": ssh_port,
        "budget_s": budget_s,
        "nodes": nodes,
        "request_file": str(request_file),
    }
    write_json(request_file, request)
    write_json(
        directory / "report.json",
        {"status": "pending", "run_id": trace.run_id, "request_id": request_id},
    )
    with (directory / "audit.log").open("ab") as log:
        child = subprocess.Popen(
            [sys.executable, str(SCRIPT), "supervise", "--request", str(request_file)],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    write_json(directory / "supervisor.json", {"pid": child.pid, "started_unix_ns": time.time_ns()})
    return directory


def launch_for_stopped_run(launcher):
    trace = getattr(launcher.backend, "trace_config", None)
    if launcher.task_type != "train" or not trace or not trace.enabled:
        return None
    if getattr(trace, "retention_window_bytes", 0):
        # The independently running recorders seal their windows and the monitor
        # checks every producer cursor in retention/report.json.
        return Path(trace.trace_dir) / "retention"
    from flagscale.runner.utils import get_nnodes, get_nproc_per_node, update_nodes_envs

    runner = launcher.config.experiment.runner
    resources = launcher.resources or {"localhost": {}}
    nnodes = get_nnodes(len(resources), runner.get("nnodes", None))
    pids = Path(launcher.config.train.system.logging.pids_dir)
    nodes = []
    for rank, (host, info) in enumerate(resources.items()):
        if rank >= nnodes:
            break
        path = pids / f"host_{rank}_{host}.pid.training.json"
        try:
            token = read_json(path).get("token")
        except (OSError, ValueError):
            token = None
        envs = getattr(launcher, "user_envs", {})
        if launcher.resources:
            envs = update_nodes_envs(envs, host, info)
        visible = next((v for k, v in envs.items() if k.endswith("_VISIBLE_DEVICES")), None)
        visible_count = len(visible.split(",")) if isinstance(visible, str) else None
        nproc = int(
            get_nproc_per_node(info.get("slots"), runner.get("nproc_per_node", None), visible_count)
        )
        nodes.append(
            {
                "node_rank": rank,
                "host": host,
                "nproc": nproc,
                "state_file": str(path),
                "token": token,
            }
        )
    return start_final_audit(trace, nodes, runner.get("ssh_port", 22))


def main():
    # Direct script execution uses the exact candidate containing this file.
    sys.path.insert(0, str(SCRIPT.parents[3]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("collect", "audit", "supervise"))
    parser.add_argument("--request", required=True)
    parser.add_argument("--node", type=int)
    args = parser.parse_args()
    request = read_json(args.request)
    if args.action == "collect":
        node = next(n for n in request["nodes"] if n["node_rank"] == args.node)
        print(json.dumps(collect_node(request, node)))
    elif args.action == "audit":
        run_audit(request, Path(args.request).with_name("report.json"))
    else:
        supervise(args.request)


if __name__ == "__main__":
    main()
