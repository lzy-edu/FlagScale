# Copyright 2026 FlagOS Contributors
# SPDX-License-Identifier: Apache-2.0
import json

from flagscale.runner.tracing.retention import NodeEvidence


def append(state, row):
    state.add(json.dumps(row).encode() + b"\n")


def cpu(i, phase):
    return dict(
        run_id="test",
        event="nccl_call",
        hostname="n",
        pid=2,
        rank=0,
        phase=phase,
        profiler_process_token=12,
        call_seq=i,
        api="ncclAllReduce",
        comm_inspector_id="ab",
        comm_rank=0,
        comm_nranks=2,
        count=3,
        datatype=7,
        profiler_bridge=True,
    )


def device(i, rev, end):
    return dict(
        record_type="flagscale_profiler_v5_v1",
        hostname="n",
        pid=2,
        process_token=12,
        call_seq=i,
        task_id=i,
        revision=rev,
        comm_id="ab",
        rank=0,
        nranks=2,
        api="AllReduce",
        count=3,
        datatype="ncclFloat32",
        peer=-1,
        invalid=False,
        graph_captured=False,
        expected_channels=1,
        channels=[dict(channel_id=0, begin=8, end=end)],
    )


def test_open_device_survives_two_independent_window_wraps():
    state = NodeEvidence("test", 2048)
    append(state, cpu(1, "enter"))
    append(state, device(1, 1, 0))
    append(state, cpu(1, "exit"))
    for i in range(2, 100):
        append(state, cpu(i, "enter"))
        append(state, device(i, 1, 9))
        append(state, cpu(i, "exit"))
    status = state.status()
    assert status["probe_bytes"] <= 2048 and status["bridge_bytes"] <= 2048
    assert not status["loss"]
    assert {r.get("event", r.get("record_type")) for r in state.snapshot(False)["pending"]} == {
        "nccl_call",
        "flagscale_profiler_v5_v1",
    }
    assert state.read(0)["first"] > 1
    evidence = state.lookup(cpu(1, "enter"))
    assert evidence["kernel_execution_status"] == "unknown"
    assert evidence["retained_device_progress"][0]["channels"] == [
        {"channel_id": 0, "begin": 8, "end": 0}
    ]
    append(state, device(1, 2, 10))
    assert state.status()["pending"] == 0


def test_confirmed_completion_is_visible_in_current_window():
    state = NodeEvidence("test", 4096)
    for row in (cpu(1, "enter"), device(1, 1, 0), device(1, 2, 9), cpu(1, "exit")):
        append(state, row)
    assert state.lookup(cpu(1, "enter"))["kernel_execution_status"] == "completed"
    assert state.status()["pin_bytes"] == 0


def test_conflicting_revision_and_capacity_are_reported():
    state = NodeEvidence("test", 2048)
    first = device(1, 1, 0)
    append(state, first)
    changed = device(1, 2, 9)
    changed["channels"][0]["begin"] = 5
    append(state, changed)
    assert state.status()["loss"]["device_revision_conflict"] == 1
    for i in range(50):
        append(state, cpu(50 + i, "enter"))
    status = state.status()
    assert status["loss"]["pending_capacity_exceeded"] > 0
    assert status["pin_bytes"] <= status["byte_budget"]
    assert state.lookup(cpu(1, "enter"))["kernel_execution_status"] == "unknown"
