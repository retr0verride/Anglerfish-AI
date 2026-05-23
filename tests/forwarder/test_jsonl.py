"""Tests for :class:`anglerfish.forwarder.JsonlSink`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from anglerfish.forwarder.errors import JsonlWriteError
from anglerfish.forwarder.jsonl import JsonlSink


async def test_write_appends_one_json_line(tmp_path: Path) -> None:
    sink = JsonlSink(tmp_path / "out.jsonl")
    await sink.write({"event": {"command": "whoami"}, "kind": "session"})
    await sink.write({"event": {"command": "id"}, "kind": "session"})
    contents = (tmp_path / "out.jsonl").read_text("utf-8").splitlines()
    assert len(contents) == 2
    assert json.loads(contents[0])["event"]["command"] == "whoami"
    assert json.loads(contents[1])["event"]["command"] == "id"


async def test_write_creates_parent_directory(tmp_path: Path) -> None:
    target = tmp_path / "deep" / "nested" / "out.jsonl"
    sink = JsonlSink(target)
    await sink.write({"x": 1})
    assert target.exists()


async def test_serialises_non_json_types_with_str_default(tmp_path: Path) -> None:
    from uuid import uuid4

    sink = JsonlSink(tmp_path / "out.jsonl")
    sid = uuid4()
    await sink.write({"session_id": sid})
    record = json.loads((tmp_path / "out.jsonl").read_text("utf-8").strip())
    assert record["session_id"] == str(sid)


async def test_size_based_rotation(tmp_path: Path) -> None:
    target = tmp_path / "out.jsonl"
    sink = JsonlSink(target, max_size_bytes=80)
    big = {"event": "x" * 60}
    await sink.write(big)
    await sink.write(big)  # rotates before this write
    await sink.write(big)
    assert target.exists()
    rotated = target.with_name(target.name + ".1")
    assert rotated.exists()


async def test_multiple_rotations_increment_index(tmp_path: Path) -> None:
    target = tmp_path / "out.jsonl"
    sink = JsonlSink(target, max_size_bytes=80)
    big = {"event": "x" * 60}
    for _ in range(4):
        await sink.write(big)
    assert target.with_name(target.name + ".1").exists()
    assert target.with_name(target.name + ".2").exists()


async def test_unserialisable_payload_raises(tmp_path: Path) -> None:
    sink = JsonlSink(tmp_path / "out.jsonl")

    class _NotJSON:
        pass

    # Using default=str rescues most exotic types, but a circular dict
    # cannot be serialised — that's a real JsonlWriteError surface.
    cycle: dict[str, object] = {}
    cycle["self"] = cycle
    with pytest.raises(JsonlWriteError):
        await sink.write(cycle)


async def test_invalid_max_size(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        JsonlSink(tmp_path / "x.jsonl", max_size_bytes=0)


async def test_properties(tmp_path: Path) -> None:
    target = tmp_path / "x.jsonl"
    sink = JsonlSink(target, max_size_bytes=1024)
    assert sink.path == target
    assert sink.max_size_bytes == 1024


async def test_os_error_wrapped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "out.jsonl"
    sink = JsonlSink(target)

    def _boom(self: object, line: bytes) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(JsonlSink, "_append_and_maybe_rotate", _boom)
    with pytest.raises(JsonlWriteError):
        await sink.write({"x": 1})
