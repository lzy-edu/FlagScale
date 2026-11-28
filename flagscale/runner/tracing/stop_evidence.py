# Copyright 2026 FlagOS Contributors
# SPDX-License-Identifier: Apache-2.0
"""Record stop observations without interpreting them as device failures."""

import argparse
import json
import os
import socket
import time
from pathlib import Path


def record_stop(directory, run_id, node_rank, event, result=None):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    record = {
        "event": event,
        "run_id": run_id,
        "node_rank": node_rank,
        "observed_at_unix_ns": time.time_ns(),
        "observer_hostname": socket.gethostname(),
        "observer_pid": os.getpid(),
        "signal": "SIGTERM" if event.startswith("worker_signal") else None,
        "dispatch_returncode": result if event.startswith("worker_signal") else None,
        "stop_returncode": result if event == "worker_stop_finished" else None,
    }
    if event == "stop_requested":
        # The monitor becomes quiet before workers are deliberately terminated.
        with (directory / "stop.requested").open("a") as marker:
            marker.write(json.dumps(record) + "\n")
            marker.flush()
            os.fsync(marker.fileno())
    with (directory / f"stop_node_{node_rank}.jsonl").open("a") as output:
        output.write(json.dumps(record) + "\n")
        output.flush()
        os.fsync(output.fileno())
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--node-rank", type=int, required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--result", type=int)
    args = parser.parse_args()
    record_stop(args.directory, args.run_id, args.node_rank, args.event, args.result)
