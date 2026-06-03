"""Cross-source consistency for the synthetic kernel identity (TODO-10).

Every surface that describes the fake box's kernel must agree. Before the
single-source refactor the lure said ``6.1.0-18-amd64`` while the bridge said
``6.1.0-26-amd64``, a tell for any attacker who cross-checked ``uname -r``,
``cat /proc/version``, and the model's narration. These tests pin that the
lure command table, the bridge fallback, the fake ``/proc/version``, and the
LLM prompt all render the one canonical release, and that the stale strings
are gone from every consumer.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from anglerfish import system_identity
from anglerfish.bridge.fallback import fallback_response
from anglerfish.bridge.prompts import build_system_prompt
from anglerfish.config.models import BridgeConfig
from anglerfish.lure.commands import LatencyJitter, NativeCommands
from anglerfish.lure.fakefs import read
from anglerfish.lure.session import LureSessionContext

# Stale strings that must never reappear once the surfaces are single-sourced.
_OLD_RELEASE = "6.1.0-18-amd64"
_OLD_BUILD = "6.1.76-1"

_SRC = Path(system_identity.__file__).resolve().parent
_CONSUMERS = (
    _SRC / "bridge" / "fallback.py",
    _SRC / "bridge" / "prompts.py",
    _SRC / "lure" / "commands.py",
    _SRC / "lure" / "fakefs.py",
)


def _session(*, hostname: str = "srv-prod-01") -> LureSessionContext:
    return LureSessionContext(
        uuid4(),
        source_ip="203.0.113.7",
        username="alice",
        hostname=hostname,
        cwd="/home/alice",
    )


def _commands() -> NativeCommands:
    from anglerfish.lure.config import LureConfig

    cfg = LureConfig(timing_jitter_enabled=False)
    return NativeCommands(cfg, jitter=LatencyJitter(cfg))


def test_uname_a_uses_single_x86_64_debian_form() -> None:
    rendered = system_identity.uname_a("host")
    # Stock Debian prints one x86_64 before GNU/Linux, not three.
    assert "x86_64 x86_64" not in rendered
    assert rendered.endswith("x86_64 GNU/Linux")
    assert system_identity.KERNEL_RELEASE in rendered
    assert system_identity.KERNEL_BUILD in rendered


def test_proc_version_constant_carries_release_and_build() -> None:
    assert system_identity.KERNEL_RELEASE in system_identity.PROC_VERSION
    assert system_identity.KERNEL_BUILD in system_identity.PROC_VERSION


def test_bridge_fallback_uname_matches_canonical() -> None:
    env = {"hostname": "srv-prod-01", "username": "root", "cwd": "/root"}
    assert fallback_response("uname -r", **env) == system_identity.KERNEL_RELEASE
    a = fallback_response("uname -a", **env)
    assert a is not None
    assert system_identity.KERNEL_RELEASE in a
    assert "x86_64 x86_64" not in a


async def test_lure_uname_matches_canonical() -> None:
    cmds = _commands()
    r = await cmds.dispatch(_session(), "uname -r")
    assert r.text.strip() == system_identity.KERNEL_RELEASE
    a = await cmds.dispatch(_session(), "uname -a")
    assert system_identity.KERNEL_RELEASE in a.text
    assert "x86_64 x86_64" not in a.text


def test_fake_proc_version_matches_canonical() -> None:
    result = read("/proc/version", _session())
    assert result.status == "content"
    assert result.content == system_identity.PROC_VERSION
    assert system_identity.KERNEL_RELEASE in result.content


def test_llm_prompt_states_canonical_kernel() -> None:
    prompt = build_system_prompt(BridgeConfig(), cwd="/root")
    assert f"- Kernel: {system_identity.KERNEL_RELEASE}" in prompt
    assert _OLD_RELEASE not in prompt


async def test_id_is_consistent_across_lure_and_fallback() -> None:
    # The non-root session user is a sudoer; lure id, fallback id, and the
    # shared helper must all agree (and match /etc/group's sudo:x:27:<user>).
    canonical = system_identity.id_line("alice")
    assert "27(sudo)" in canonical

    fallback = fallback_response("id", hostname="h", username="alice", cwd="/home/alice")
    assert fallback == canonical

    session = LureSessionContext(
        uuid4(),
        source_ip="203.0.113.7",
        username="alice",
        hostname="srv-prod-01",
        cwd="/home/alice",
    )
    lure = await _commands().dispatch(session, "id")
    assert lure.text.strip() == canonical


def test_no_consumer_carries_the_stale_kernel_strings() -> None:
    for path in _CONSUMERS:
        text = path.read_text(encoding="utf-8")
        assert _OLD_RELEASE not in text, f"{path.name} still hard-codes {_OLD_RELEASE}"
        assert _OLD_BUILD not in text, f"{path.name} still hard-codes {_OLD_BUILD}"
