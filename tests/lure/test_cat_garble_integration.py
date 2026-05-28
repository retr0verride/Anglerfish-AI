"""Stage 12 slice 12.3: _cat handler garble integration.

Drives the native ``cat`` dispatch against a session that has
counter-deception garble paths populated (the bridge ships these on
SessionStartResponse when an IP engaged on a prior session). Verifies
the served bytes are corrupted, the DispatchResult carries the
GarbleServed metadata the server audits, and that non-engaged sessions
+ non-allowlisted paths stay pristine.
"""

from __future__ import annotations

from uuid import uuid4

from anglerfish.lure.commands import LatencyJitter, NativeCommands
from anglerfish.lure.config import LureConfig
from anglerfish.lure.session import LureSessionContext

_AWS_CREDS = (
    "[default]\n"
    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    "region = us-east-1\n"
)
_AWS_PATH = "/root/.aws/credentials"


def _commands() -> NativeCommands:
    cfg = LureConfig(timing_jitter_enabled=False)
    return NativeCommands(cfg, jitter=LatencyJitter(cfg))


def _session(*, garble_paths: frozenset[str] = frozenset()) -> LureSessionContext:
    return LureSessionContext(
        uuid4(),
        source_ip="203.0.113.7",
        username="root",
        hostname="srv-prod-01",
        cwd="/root",
        persona_overlay={_AWS_PATH: _AWS_CREDS},
        counter_deception_garble_paths=garble_paths,
    )


async def test_cat_garbles_allowlisted_path() -> None:
    session = _session(garble_paths=frozenset({_AWS_PATH}))
    result = await _commands().dispatch(session, f"cat {_AWS_PATH}")
    assert result.handled
    assert result.garble is not None
    assert result.garble.kind == "aws"
    assert result.garble.path == _AWS_PATH
    assert result.garble.original_chars == len(_AWS_CREDS)
    # AKIA prefix preserved, secret mangled.
    assert "AKIAIOSFODNN7EXAMPLE" in result.text
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in result.text


async def test_cat_same_session_same_garble_on_reread() -> None:
    session = _session(garble_paths=frozenset({_AWS_PATH}))
    cmds = _commands()
    first = await cmds.dispatch(session, f"cat {_AWS_PATH}")
    second = await cmds.dispatch(session, f"cat {_AWS_PATH}")
    assert first.text == second.text


async def test_cat_non_allowlisted_path_is_pristine() -> None:
    """A session with garble paths set still serves OTHER files clean."""
    session = LureSessionContext(
        uuid4(),
        source_ip="203.0.113.7",
        username="root",
        hostname="srv-prod-01",
        cwd="/root",
        persona_overlay={
            _AWS_PATH: _AWS_CREDS,
            "/root/notes.txt": "plain notes\n",
        },
        counter_deception_garble_paths=frozenset({_AWS_PATH}),
    )
    result = await _commands().dispatch(session, "cat /root/notes.txt")
    assert result.handled
    assert result.garble is None
    assert result.text == "plain notes\n"


async def test_cat_pristine_when_session_not_engaged() -> None:
    """Default-off: no garble paths -> served content is untouched."""
    session = _session(garble_paths=frozenset())
    result = await _commands().dispatch(session, f"cat {_AWS_PATH}")
    assert result.handled
    assert result.garble is None
    assert result.text == _AWS_CREDS


async def test_cat_garble_only_affects_exact_path() -> None:
    """A garble-path entry does not corrupt a sibling under the same dir."""
    session = LureSessionContext(
        uuid4(),
        source_ip="203.0.113.7",
        username="root",
        hostname="srv-prod-01",
        cwd="/root",
        persona_overlay={
            _AWS_PATH: _AWS_CREDS,
            "/root/.aws/config": "[profile x]\nregion = us-east-1\n",
        },
        counter_deception_garble_paths=frozenset({_AWS_PATH}),
    )
    cmds = _commands()
    creds = await cmds.dispatch(session, f"cat {_AWS_PATH}")
    config = await cmds.dispatch(session, "cat /root/.aws/config")
    assert creds.garble is not None
    assert config.garble is None
    assert config.text == "[profile x]\nregion = us-east-1\n"
