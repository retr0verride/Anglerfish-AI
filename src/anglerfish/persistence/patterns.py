"""Regex catalog + payload extraction for the Stage 10 classifier.

This module is the synchronous hot path: every attacker command
hits :func:`extract_event` before the bridge issues an LLM call.
Patterns are tuned to extract the persistence payload (cron
line, unit name, SSH key) verbatim from the attacker's bash
command - the Stage 4 threat scorer (in
``anglerfish/threat/techniques.py``) already pattern-matches
*that* a persistence attempt happened; Stage 10 extends with
*what* was installed so subsequent ``crontab -l``,
``systemctl status``, ``cat ~/.ssh/authorized_keys`` can render
consistent output.

Three kinds of patterns, in detection order (the first to match
wins):

1. ``authorized_keys``: ``echo '<key>' >> ~/.ssh/authorized_keys``
   and the ``tee -a`` / ``printf >>`` variants.
2. ``crontab``: ``echo '<line>' | crontab -``, ``crontab
   <file>``, ``(crontab -l; echo '<line>') | crontab -``, plus
   raw writes to ``/etc/cron.d/*`` and ``/var/spool/cron/*``.
3. ``systemctl``: ``systemctl enable <unit>``, ``systemctl
   start <unit>``, ``service <unit> start``, plus raw writes to
   ``/etc/systemd/system/*.service``.

Misses (no regex matches, or matches but no payload could be
extracted cleanly) return :data:`None`. The classifier then
falls through to the LLM pass (slice 10.3) or to the normal
command pipeline.

The regexes deliberately stay conservative: false positives on
the engaged-persistence path are louder than false negatives
(an over-detected install gets reflected at the attacker, which
is fine; a missed install just degrades to the same shape the
pre-Stage-10 bridge had).
"""

from __future__ import annotations

import re

from anglerfish.models.persistence import PersistenceEvent

__all__ = ["extract_event"]


# ---------------------------------------------------------------------------
# authorized_keys patterns
# ---------------------------------------------------------------------------

# Captures the appended SSH key from any of:
#   echo 'KEY' >> ~/.ssh/authorized_keys
#   echo "KEY" >> /home/user/.ssh/authorized_keys
#   echo KEY >> /root/.ssh/authorized_keys
#   printf '%s\n' 'KEY' >> ~/.ssh/authorized_keys
#   echo 'KEY' | tee -a ~/.ssh/authorized_keys
#
# group 1 = quoted-single, group 2 = quoted-double, group 3 = unquoted,
# group 4 = user (from /home/<user>/ path; None for ~ or /root).
_AUTHORIZED_KEYS_ECHO = re.compile(
    r"""
    \becho\s+                                    # echo command
    (?:
        '([^']+)'                                # group 1: single-quoted key
      | "([^"]+)"                                # group 2: double-quoted key
      | (\S+(?:\s+\S+){0,3})                     # group 3: unquoted (up to 4 toks)
    )
    \s*(?:>>|\|\s*tee\s+-a)\s*                   # append (>> or | tee -a)
    (?:~|/root|/home/(\S+?))                     # group 4: optional user
    /\.ssh/authorized_keys                       # the file
    """,
    re.VERBOSE,
)

# Captures the appended key from a `printf '%s\n' 'KEY' >> ...` shape.
# The printf variant is rare but worth catching because OpenSSH
# tutorials suggest it.
_AUTHORIZED_KEYS_PRINTF = re.compile(
    r"""
    \bprintf\s+(?:'[^']*'|"[^"]*")\s+            # printf format string
    (?:
        '([^']+)'                                # group 1: single-quoted key
      | "([^"]+)"                                # group 2: double-quoted key
    )
    \s*>>\s*
    (?:~|/root|/home/(\S+?))                     # group 3: optional user
    /\.ssh/authorized_keys
    """,
    re.VERBOSE,
)


# ---------------------------------------------------------------------------
# crontab patterns
# ---------------------------------------------------------------------------

# Captures the cron line from:
#   echo 'LINE' | crontab -
#   echo "LINE" | crontab -
#   (crontab -l; echo 'LINE') | crontab -
#
# group 1 = quoted-single, group 2 = quoted-double.
_CRONTAB_PIPE = re.compile(
    r"""
    \becho\s+
    (?:
        '([^']+)'                                # group 1
      | "([^"]+)"                                # group 2
    )
    \s*[);\s]*                                   # optional ) ; whitespace
    \|\s*crontab\s+-\s*$
    """,
    re.VERBOSE,
)

# Captures `crontab -e` with no payload (interactive edit). We
# record the install with payload="<interactive edit>" so the
# operator sees something happened; the LLM pass in slice 10.3
# may refine this.
_CRONTAB_INTERACTIVE = re.compile(r"^\s*crontab\s+(?:-e|--edit)\s*$")

# Captures `crontab FILE` (replace from a path). We record the
# path; the fake-state replay layer reads the file via the
# fakefs to surface it.
_CRONTAB_REPLACE_FROM_FILE = re.compile(
    r"^\s*crontab\s+(/\S+)\s*$",
)

# Captures raw writes to cron-spool / cron.d.
# Matches:
#   echo 'LINE' >> /etc/cron.d/backdoor
#   echo "LINE" >> /var/spool/cron/crontabs/root
_CRONTAB_RAW_WRITE = re.compile(
    r"""
    \becho\s+
    (?:
        '([^']+)'                                # group 1
      | "([^"]+)"                                # group 2
    )
    \s*>>\s*
    (?:/etc/cron(?:tab|\.d/\S+)|/var/spool/cron/(?:crontabs/)?\S+)
    """,
    re.VERBOSE,
)


# ---------------------------------------------------------------------------
# systemctl patterns
# ---------------------------------------------------------------------------

# Captures the unit name from `systemctl enable|start [--now] <unit>`.
# Skips any leading dash-prefixed flags (--now, --no-reload, etc.)
# before capturing. group 1 = unit (with optional .service suffix).
_SYSTEMCTL_ENABLE_START = re.compile(
    r"""
    \bsystemctl\s+
    (?:enable|start)\s+
    (?:--\S+\s+)*                                # optional dash-flags
    (\S+?)                                       # group 1: unit name
    (?:\.service)?\b
    """,
    re.VERBOSE,
)

# Captures `service NAME start|enable` (sysvinit-style).
_SERVICE_START = re.compile(
    r"\bservice\s+(\S+)\s+(?:start|enable|restart)\b",
)

# Captures raw writes to /etc/systemd/system/<unit>.service.
# The payload is the install path itself (the unit content
# might be on the next line in a multi-line attacker script;
# regex extraction stays single-line).
_SYSTEMD_UNIT_WRITE = re.compile(
    r"""
    (?:>>?|tee\s+(?:-a\s+)?)\s*
    (/etc/systemd/system/(\S+?\.service))
    """,
    re.VERBOSE,
)


# ---------------------------------------------------------------------------
# Public extraction
# ---------------------------------------------------------------------------


def extract_event(command: str) -> PersistenceEvent | None:
    """Return a :class:`PersistenceEvent` if ``command`` installs persistence.

    First-match-wins across the three kinds (authorized_keys ->
    crontab -> systemctl). Returns :data:`None` on no match;
    the classifier then falls through to the LLM pass (slice
    10.3) or to the normal pipeline.

    The matchers are intentionally conservative: a false
    negative degrades to pre-Stage-10 behaviour (no fake
    state), while a false positive over-engages (LLM is told
    the attacker installed something they did not, which is a
    minor consistency issue but not a security regression).
    """
    if not command or not command.strip():
        return None

    event = _try_authorized_keys(command)
    if event is not None:
        return event

    event = _try_crontab(command)
    if event is not None:
        return event

    return _try_systemctl(command)


# ---------------------------------------------------------------------------
# Per-kind extractors (kept small + single-purpose)
# ---------------------------------------------------------------------------


def _try_authorized_keys(command: str) -> PersistenceEvent | None:
    match = _AUTHORIZED_KEYS_ECHO.search(command)
    if match is not None:
        key = _first_non_none(match.group(1), match.group(2), match.group(3))
        sub_key = match.group(4)
        if key:
            return PersistenceEvent(
                kind="authorized_keys",
                sub_key=sub_key,
                payload=key.strip(),
                source="regex",
            )

    match = _AUTHORIZED_KEYS_PRINTF.search(command)
    if match is not None:
        key = _first_non_none(match.group(1), match.group(2))
        sub_key = match.group(3)
        if key:
            return PersistenceEvent(
                kind="authorized_keys",
                sub_key=sub_key,
                payload=key.strip(),
                source="regex",
            )

    return None


def _try_crontab(command: str) -> PersistenceEvent | None:
    match = _CRONTAB_PIPE.search(command)
    if match is not None:
        line = _first_non_none(match.group(1), match.group(2))
        if line:
            return PersistenceEvent(
                kind="crontab",
                sub_key=None,
                payload=line.strip(),
                source="regex",
            )

    match = _CRONTAB_RAW_WRITE.search(command)
    if match is not None:
        line = _first_non_none(match.group(1), match.group(2))
        if line:
            return PersistenceEvent(
                kind="crontab",
                sub_key=None,
                payload=line.strip(),
                source="regex",
            )

    match = _CRONTAB_INTERACTIVE.search(command)
    if match is not None:
        return PersistenceEvent(
            kind="crontab",
            sub_key=None,
            payload="<interactive edit>",
            source="regex",
        )

    match = _CRONTAB_REPLACE_FROM_FILE.search(command)
    if match is not None:
        return PersistenceEvent(
            kind="crontab",
            sub_key=None,
            payload=f"<replace from {match.group(1)}>",
            source="regex",
        )

    return None


def _try_systemctl(command: str) -> PersistenceEvent | None:
    match = _SYSTEMCTL_ENABLE_START.search(command)
    if match is not None:
        unit = match.group(1)
        if unit:
            return PersistenceEvent(
                kind="systemctl",
                sub_key=unit,
                payload=unit,
                source="regex",
            )

    match = _SERVICE_START.search(command)
    if match is not None:
        unit = match.group(1)
        if unit:
            return PersistenceEvent(
                kind="systemctl",
                sub_key=unit,
                payload=unit,
                source="regex",
            )

    match = _SYSTEMD_UNIT_WRITE.search(command)
    if match is not None:
        path = match.group(1)
        unit = match.group(2)
        return PersistenceEvent(
            kind="systemctl",
            sub_key=unit,
            payload=f"<unit file written to {path}>",
            source="regex",
        )

    return None


def _first_non_none(*values: str | None) -> str | None:
    for v in values:
        if v is not None:
            return v
    return None
