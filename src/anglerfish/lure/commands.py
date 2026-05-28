"""Native command dispatch for the lure.

Every command the lure sees passes through :func:`first_token`. If
the token matches a key in :data:`_HANDLERS`, the lure handles the
command in-process (cheap, no LLM call). Anything else gets routed to
the bridge via :class:`anglerfish.lure.bridge_client.BridgeClient`.

The dispatch table is intentionally short. Listing fifty native
commands would mean re-implementing busybox. The lure handles the
canonical reconnaissance verbs (whoami, id, pwd, ls, cd, uname,
hostname, echo, history, cat-of-known-paths, exit) and the LLM
absorbs everything else.

The :class:`LatencyJitter` wrapper around each native handler keeps
native and bridge response times statistically indistinguishable so
the dispatch table is not an attacker fingerprint. See
``docs/design/STAGE_2_lure_subsystem.md`` "Native-command timing
jitter" for the rationale.
"""

from __future__ import annotations

import asyncio
import math
import random
import shlex
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final

from anglerfish.bridge.path import normalise_path
from anglerfish.lure.config import LureConfig
from anglerfish.lure.fakefs import listdir, read
from anglerfish.lure.garble import garble
from anglerfish.lure.session import LureSessionContext

__all__ = [
    "DispatchResult",
    "GarbleServed",
    "LatencyJitter",
    "NativeCommands",
    "first_token",
]


@dataclass(frozen=True)
class GarbleServed:
    """Counter-deception garble metadata for one ``cat`` (Stage 12).

    Carried on :class:`DispatchResult` so the server (which holds the
    AuditLog) can record ``lure.counter_deception_garble_served`` after
    dispatch. The handler stays free of audit-logging concerns.
    """

    path: str
    kind: str
    original_chars: int
    garbled_chars: int


@dataclass(frozen=True)
class DispatchResult:
    """Outcome of a native dispatch attempt.

    ``handled`` is False when no native handler matched and the caller
    should route the command to the bridge. ``text`` is the response
    body the attacker sees, empty for handlers like ``cd`` that have
    no stdout. ``close_after`` is True only for ``exit``: the asyncssh
    channel handler closes the session after delivering ``text``.
    ``garble`` is set only when the ``cat`` handler corrupted the file
    for a counter-deception-engaged session (Stage 12); the server
    records the audit event from it.
    """

    handled: bool
    text: str = ""
    close_after: bool = False
    garble: GarbleServed | None = None


def first_token(command: str) -> str:
    """Return the first shell token of ``command`` or '' for empty input.

    Uses :func:`shlex.split` so quoted arguments parse correctly. Falls
    back to whitespace split if shlex raises (unclosed quotes etc.).
    Returns ``""`` for empty input so the caller knows there is no
    command to dispatch (bash would just emit the next prompt).
    """
    stripped = command.strip()
    if not stripped:
        return ""
    try:
        tokens = shlex.split(stripped, posix=True)
    except ValueError:
        parts = stripped.split(maxsplit=1)
        return parts[0] if parts else ""
    return tokens[0] if tokens else ""


# ---------------------------------------------------------------------------
# LatencyJitter
# ---------------------------------------------------------------------------


class LatencyJitter:
    """Per-process EWMA of observed bridge latency, used to delay native
    command responses so they look indistinguishable from bridge ones.

    Two phases:

    1. **Bootstrap** (before enough bridge samples land): sleep for a
       uniform random ms in the configured bootstrap range. Defence
       is up from request one.
    2. **EWMA** (after ``min_samples_before_ewma`` bridge samples
       arrive): sleep for a log-normal sample centred on the running
       EWMA median, clamped to the configured floor and ceiling.

    Per-process, not per-session: a single attacker opening many
    sessions still sees one distribution.

    The PRNG is :mod:`random`, which is fine for jitter: an attacker
    learning the seed buys nothing useful. ``# noqa: S311`` notes
    below mark each insecure-random call as intentional.
    """

    def __init__(self, config: LureConfig) -> None:
        self._enabled = config.timing_jitter_enabled
        self._floor_ms = config.timing_jitter_floor_ms
        self._ceiling_ms = config.timing_jitter_ceiling_ms
        self._bootstrap_min_ms = config.timing_jitter_bootstrap_min_ms
        self._bootstrap_max_ms = config.timing_jitter_bootstrap_max_ms
        self._ewma_alpha = 0.2
        self._min_samples_before_ewma = 5
        self._recent: deque[float] = deque(maxlen=200)
        self._ewma_ms: float | None = None

    def record_bridge_latency(self, latency_ms: float) -> None:
        """Feed an observed bridge latency into the EWMA."""
        if latency_ms < 0:
            return
        clamped = min(latency_ms, float(self._ceiling_ms))
        self._recent.append(clamped)
        if self._ewma_ms is None:
            self._ewma_ms = clamped
        else:
            self._ewma_ms = self._ewma_alpha * clamped + (1.0 - self._ewma_alpha) * self._ewma_ms

    def sample_native_delay_ms(self) -> float:
        """Return how long the caller should sleep before responding."""
        if not self._enabled:
            return 0.0
        if self._ewma_ms is None or len(self._recent) < self._min_samples_before_ewma:
            return float(
                random.uniform(  # noqa: S311 - jitter PRNG, security-irrelevant
                    self._bootstrap_min_ms,
                    self._bootstrap_max_ms,
                ),
            )
        mu = math.log(max(self._ewma_ms, 1.0))
        raw = random.lognormvariate(mu, 0.4)
        return float(min(max(raw, float(self._floor_ms)), float(self._ceiling_ms)))

    async def sleep_native(self) -> None:
        """Sleep ``sample_native_delay_ms()`` ms via ``asyncio.sleep``."""
        delay_ms = self.sample_native_delay_ms()
        if delay_ms > 0:
            await asyncio.sleep(delay_ms / 1000.0)


# ---------------------------------------------------------------------------
# Native handlers (module-level so the dispatch dict does not access
# private class members; the staticmethod pattern was tripping SLF001).
# ---------------------------------------------------------------------------


async def _whoami(session: LureSessionContext, _tokens: list[str]) -> DispatchResult:
    return DispatchResult(handled=True, text=f"{session.username}\n")


async def _id(session: LureSessionContext, _tokens: list[str]) -> DispatchResult:
    if session.username == "root":
        text = "uid=0(root) gid=0(root) groups=0(root)\n"
    else:
        text = (
            f"uid=1000({session.username}) gid=1000({session.username}) "
            f"groups=1000({session.username}),27(sudo)\n"
        )
    return DispatchResult(handled=True, text=text)


async def _pwd(session: LureSessionContext, _tokens: list[str]) -> DispatchResult:
    return DispatchResult(handled=True, text=f"{session.cwd}\n")


async def _hostname(session: LureSessionContext, _tokens: list[str]) -> DispatchResult:
    return DispatchResult(handled=True, text=f"{session.hostname}\n")


async def _uname(session: LureSessionContext, tokens: list[str]) -> DispatchResult:
    kernel = "6.1.0-18-amd64"
    if len(tokens) == 1:
        return DispatchResult(handled=True, text="Linux\n")
    flag = tokens[1]
    if flag == "-a":
        text = (
            f"Linux {session.hostname} {kernel} #1 SMP PREEMPT_DYNAMIC "
            "Debian 6.1.76-1 (2024-02-01) x86_64 GNU/Linux\n"
        )
        return DispatchResult(handled=True, text=text)
    if flag == "-r":
        return DispatchResult(handled=True, text=f"{kernel}\n")
    if flag == "-n":
        return DispatchResult(handled=True, text=f"{session.hostname}\n")
    if flag == "-s":
        return DispatchResult(handled=True, text="Linux\n")
    if flag == "-m":
        return DispatchResult(handled=True, text="x86_64\n")
    # Anything else (-o, -v, etc.) goes to the bridge.
    return DispatchResult(handled=False)


async def _echo(_session: LureSessionContext, tokens: list[str]) -> DispatchResult:
    body = " ".join(tokens[1:])
    return DispatchResult(handled=True, text=body + "\n")


async def _exit(_session: LureSessionContext, _tokens: list[str]) -> DispatchResult:
    # Empty body; the channel handler closes the SSH session after
    # delivering an empty response. Routing through the bridge would
    # add ~1s of artificial latency that deviates from real sshd
    # behaviour; attackers and automated scripts expect the socket to
    # drop instantly.
    return DispatchResult(handled=True, text="", close_after=True)


async def _history(session: LureSessionContext, _tokens: list[str]) -> DispatchResult:
    lines = [f"{i:5d}  {record.command}" for i, record in enumerate(session.history(), start=1)]
    text = "\n".join(lines) + ("\n" if lines else "")
    return DispatchResult(handled=True, text=text)


async def _cd(session: LureSessionContext, tokens: list[str]) -> DispatchResult:
    if len(tokens) == 1 or tokens[1] == "~":
        target = f"/home/{session.username}" if session.username != "root" else "/root"
    elif tokens[1].startswith("/"):
        target = tokens[1]
    else:
        base = session.cwd.rstrip("/") or "/"
        target = f"{base}/{tokens[1]}"
    session.update_cwd(normalise_path(target))
    return DispatchResult(handled=True, text="")


async def _ls(session: LureSessionContext, tokens: list[str]) -> DispatchResult:
    long_form = False
    show_hidden = False
    path: str | None = None
    for arg in tokens[1:]:
        if arg.startswith("-"):
            if "l" in arg:
                long_form = True
            if "a" in arg:
                show_hidden = True
            if any(c not in "-la" for c in arg):
                return DispatchResult(handled=False)
        elif path is None:
            path = arg
        else:
            return DispatchResult(handled=False)

    target = normalise_path(path) if path else session.cwd
    listing = listdir(target, session)
    if listing.status != "entries":
        return DispatchResult(handled=False)

    visible = [e for e in listing.entries if show_hidden or not e.name.startswith(".")]
    if not long_form:
        text = "  ".join(e.name for e in visible) + ("\n" if visible else "")
        return DispatchResult(handled=True, text=text)

    lines = []
    for e in visible:
        kind = "d" if e.is_dir else ("l" if e.is_symlink else "-")
        perms = _render_mode_bits(e.mode)
        link_target = f" -> {e.target}" if e.is_symlink and e.target else ""
        lines.append(
            f"{kind}{perms} 1 {e.owner:>8} {e.group:>8} "
            f"{e.size:>8} May 23 14:01 {e.name}{link_target}",
        )
    text = "\n".join(lines) + ("\n" if lines else "")
    return DispatchResult(handled=True, text=text)


async def _cat(session: LureSessionContext, tokens: list[str]) -> DispatchResult:
    # Only single-file cat with no flags is native. Anything more
    # (multiple files, -n, -A, etc.) goes to the bridge.
    if len(tokens) != 2 or tokens[1].startswith("-"):
        return DispatchResult(handled=False)
    target = tokens[1]
    if not target.startswith("/"):
        base = session.cwd.rstrip("/") or "/"
        target = f"{base}/{target}"
    target = normalise_path(target)
    read_result = read(target, session)
    if read_result.status == "content":
        # Stage 12: corrupt the served bytes when counter-deception
        # engaged for this session AND this path is in the allowlist.
        # garble() is deterministic per (session_id, path) so repeated
        # cats of the same file return identical corruption.
        if target in session.counter_deception_garble_paths:
            result = garble(read_result.content, session_id=session.session_id, path=target)
            return DispatchResult(
                handled=True,
                text=result.content,
                garble=GarbleServed(
                    path=target,
                    kind=result.kind.value,
                    original_chars=result.original_chars,
                    garbled_chars=result.garbled_chars,
                ),
            )
        return DispatchResult(handled=True, text=read_result.content)
    if read_result.status == "permission_denied":
        return DispatchResult(
            handled=True,
            text=f"cat: {tokens[1]}: Permission denied\n",
        )
    return DispatchResult(handled=False)


def _render_mode_bits(mode: int) -> str:
    """Render the low nine bits of ``mode`` as ``rwxrwxrwx``."""
    bits = mode & 0o777
    out: list[str] = []
    for shift in (6, 3, 0):
        triple = (bits >> shift) & 0o7
        out.append("r" if triple & 0o4 else "-")
        out.append("w" if triple & 0o2 else "-")
        out.append("x" if triple & 0o1 else "-")
    return "".join(out)


NativeHandler = Callable[
    [LureSessionContext, list[str]],
    Awaitable[DispatchResult],
]


_HANDLERS: Final[dict[str, NativeHandler]] = {
    "whoami": _whoami,
    "id": _id,
    "pwd": _pwd,
    "hostname": _hostname,
    "uname": _uname,
    "echo": _echo,
    "exit": _exit,
    "logout": _exit,  # alias
    "history": _history,
    "cd": _cd,
    "ls": _ls,
    "cat": _cat,
}


class NativeCommands:
    """Bound dispatch table.

    Construct once at server startup, share across sessions. The
    :class:`LatencyJitter` instance is process-wide so a single
    attacker opening many sessions still sees one timing distribution.
    """

    def __init__(self, config: LureConfig, jitter: LatencyJitter | None = None) -> None:
        self._config = config
        self._jitter = jitter if jitter is not None else LatencyJitter(config)

    @property
    def jitter(self) -> LatencyJitter:
        return self._jitter

    async def dispatch(
        self,
        session: LureSessionContext,
        command: str,
    ) -> DispatchResult:
        """Return a native verdict for ``command``.

        ``handled=False`` means the caller should route to the bridge.
        Empty input returns ``handled=True, text=""`` so the caller
        emits a fresh prompt without involving the bridge.
        """
        stripped = command.strip()
        if not stripped:
            return DispatchResult(handled=True, text="")

        # Pipes and semicolons short-circuit to the bridge so the LLM
        # produces a plausible composite answer better than the
        # deliberately-minimal native handlers could fake.
        if any(sep in stripped for sep in ("|", ";", "&&", "||")):
            return DispatchResult(handled=False)

        token = first_token(stripped)
        handler = _HANDLERS.get(token)
        if handler is None:
            return DispatchResult(handled=False)

        try:
            tokens = shlex.split(stripped, posix=True)
        except ValueError:
            tokens = stripped.split()

        dispatch_result = await handler(session, tokens)
        if dispatch_result.handled:
            await self._jitter.sleep_native()
        return dispatch_result

    def record_bridge_latency(self, latency_ms: float) -> None:
        """Forward to the jitter EWMA. Convenience for server.py."""
        self._jitter.record_bridge_latency(latency_ms)
