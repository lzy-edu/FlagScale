# Copyright 2026 FlagOS Contributors
# SPDX-License-Identifier: Apache-2.0
"""Producer seals and bounded online reconciliation for normal exit and stop.

The diagnostic wrapper publishes only after its supervised launcher has exited.
It never waits for the monitor (the stop supervisor waits for the wrapper). The
monitor waits for every declared node and verifies immutable copies before its
canonical final report. File completeness is distinct from GPU completion.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from flagscale.runner.tracing.final_evidence import (
    audit_snapshots,
    collect_node,
    error_record,
    read_json,
    write_json,
)


def publish(trace_dir, run_id, node_rank, nproc, state_file, inspector_dir, bridge):
    """Seal final files on their producer host; a failed seal stays explicit."""
    request = dict(
        run_id=run_id,
        request_id=run_id,
        trace_dir=str(trace_dir),
        inspector_dir=inspector_dir,
        bridge_enabled=bridge,
    )
    try:
        state = read_json(state_file)
        node = dict(node_rank=node_rank, nproc=nproc, state_file=state_file, token=state["token"])
        # The wrapper is still recording this seal. Training, launcher and
        # supervisor must already be gone; do not introduce a circular wait.
        manifest = collect_node(request, node, allow_wrapper=True, sync_files=True)
    except Exception as exc:
        manifest = dict(
            run_id=run_id,
            request_id=run_id,
            node_rank=node_rank,
            errors=[error_record(exc, stage="publication")],
            files=[],
            producers=[],
        )
    manifest["expected_local_ranks"] = nproc
    path = Path(trace_dir) / f"sealed_node_{node_rank}.json"
    write_json(path, manifest)
    with path.open("rb") as stream:
        os.fsync(stream.fileno())
    return manifest


def load_seals(trace_dir, run_id, nodes):
    manifests, missing, errors = [], [], []
    for rank in range(nodes):
        path = Path(trace_dir) / f"sealed_node_{rank}.json"
        try:
            manifest = read_json(path)
            if manifest.get("run_id") != run_id or manifest.get("node_rank") != rank:
                raise ValueError("seal_identity_mismatch")
            manifests.append(manifest)
            errors.extend(manifest.get("errors", []))
        except FileNotFoundError:
            missing.append(rank)
        except (OSError, ValueError) as exc:
            missing.append(rank)
            errors.append(error_record(exc, node_rank=rank, stage="seal_read"))
    return manifests, missing, errors


def reconcile(request, output):
    started = time.monotonic()
    deadline = started + request["budget_s"]
    hosts = request.get("peer_hosts", [])
    received, last_errors = {}, {}
    while time.monotonic() < deadline:
        for rank in range(request["nodes"]):
            if rank in received:
                continue
            try:
                if rank and hosts and hosts[rank] != "localhost":
                    command = [
                        "env",
                        "PYTHONPATH=" + str(Path(__file__).resolve().parents[3]),
                        sys.executable,
                        "-m",
                        "flagscale.runner.tracing.shutdown",
                        "read-seal",
                        "--trace-dir",
                        request["trace_dir"],
                        "--run-id",
                        request["run_id"],
                        "--node-rank",
                        str(rank),
                    ]
                    reply = subprocess.run(
                        [
                            "ssh",
                            "-o",
                            "BatchMode=yes",
                            "-o",
                            "ConnectTimeout=2",
                            "-p",
                            str(request.get("ssh_port", 22)),
                            hosts[rank],
                            shlex.join(command),
                        ],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=max(0.01, min(2, deadline - time.monotonic())),
                    )
                    manifest = json.loads(reply.stdout)
                else:
                    manifest = read_json(Path(request["trace_dir"]) / f"sealed_node_{rank}.json")
                if manifest.get("run_id") != request["run_id"] or manifest.get("node_rank") != rank:
                    raise ValueError("seal_identity_mismatch")
                received[rank] = manifest
                last_errors.pop(rank, None)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                last_errors[rank] = error_record(exc, stage="seal_read", node_rank=rank)
        if len(received) == request["nodes"]:
            break
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    manifests = [received[k] for k in sorted(received)]
    missing = sorted(set(range(request["nodes"])) - received.keys())
    errors = [*last_errors.values(), *(e for m in manifests for e in m.get("errors", []))]
    declared = {f["path"] for m in manifests for f in m.get("files", [])}
    errors.extend(
        e for m in manifests for e in m.get("unclassified_files", []) if e["path"] not in declared
    )
    report = dict(
        run_id=request["run_id"],
        status="incomplete",
        missing_nodes=missing,
        errors=errors,
        nodes=manifests,
        scope="sealed_producer_files_not_proof_all_device_tasks_completed",
    )
    ranks = [p["rank"] for m in manifests for p in m.get("producers", [])]
    expected = sum(m.get("expected_local_ranks", 0) for m in manifests)
    if not missing and (not expected or sorted(ranks) != list(range(expected))):
        errors.append(dict(stage="producer_coverage", error="global_ranks_incomplete_or_duplicate"))
    if not missing and not errors and time.monotonic() < deadline:
        with tempfile.TemporaryDirectory(
            prefix="flagscale-online-seal-", dir="/tmp" if Path("/tmp").is_dir() else None
        ) as tmp:
            report["audit"] = audit_snapshots(request, manifests, Path(tmp), deadline)
        errors.extend(report["audit"]["errors"])
        if not errors:
            report["status"] = "files_verified"
    report["elapsed_s"] = time.monotonic() - started
    write_json(output, report)
    return report


def finish_online(trace_dir, run_id, nodes, inspector_dir, budget_s, *, peer_hosts=(), ssh_port=22):
    """Isolate blocking filesystem work under a parent-enforced time limit."""
    output = Path(trace_dir) / "online.final.json"
    request_file = Path(trace_dir) / "online.final.request.json"
    request = dict(
        trace_dir=str(trace_dir),
        run_id=run_id,
        request_id=run_id,
        nodes=nodes,
        inspector_dir=str(inspector_dir) if inspector_dir else "",
        budget_s=budget_s,
        peer_hosts=list(peer_hosts),
        ssh_port=ssh_port,
    )
    write_json(request_file, request)
    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "flagscale.runner.tracing.shutdown",
                "reconcile",
                "--request",
                str(request_file),
                "--output",
                str(output),
            ],
            check=True,
            timeout=budget_s + 1,
            stdin=subprocess.DEVNULL,
        )
        result = read_json(output)
        if result.get("run_id") != run_id:
            raise ValueError("online_report_wrong_run")
        return result
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result = dict(
            run_id=run_id,
            status="incomplete",
            errors=[error_record(exc, stage="online_reconciliation")],
        )
        write_json(output, result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    pub = sub.add_parser("publish")
    for name in ("trace-dir", "run-id", "state-file"):
        pub.add_argument("--" + name, required=True)
    pub.add_argument("--node-rank", type=int, required=True)
    pub.add_argument("--nproc", type=int, required=True)
    pub.add_argument("--inspector-dir", default="")
    pub.add_argument("--bridge", action="store_true")
    rec = sub.add_parser("reconcile")
    rec.add_argument("--request", required=True)
    rec.add_argument("--output", required=True)
    read = sub.add_parser("read-seal")
    read.add_argument("--trace-dir", required=True)
    read.add_argument("--run-id", required=True)
    read.add_argument("--node-rank", type=int, required=True)
    args = vars(parser.parse_args())
    action = args.pop("action")
    if action == "publish":
        publish(**args)
    elif action == "read-seal":
        seal = read_json(Path(args["trace_dir"]) / f"sealed_node_{args['node_rank']}.json")
        if seal.get("run_id") != args["run_id"] or seal.get("node_rank") != args["node_rank"]:
            raise ValueError("seal_identity_mismatch")
        print(json.dumps(seal))
    else:
        reconcile(read_json(args["request"]), args["output"])


if __name__ == "__main__":
    main()
