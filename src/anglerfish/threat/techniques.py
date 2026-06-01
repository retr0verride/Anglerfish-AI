"""MITRE ATT&CK technique detection rules.

The rule set is deliberately conservative — every entry has a stable
ATT&CK technique identifier so threat-intel consumers can correlate
Anglerfish observations with other sources. Adding a new rule means
adding a new :class:`TechniqueRule` here; the scorer pulls in
:data:`TECHNIQUES` unconditionally.

Two kinds of matches are supported per rule:

* ``commands`` — exact command-name match against the first token of
  the command line (after :mod:`shlex` parsing). Absolute paths are
  collapsed to the basename so ``/usr/bin/whoami`` and ``whoami`` both
  match the rule.
* ``command_patterns`` — regex applied to the full command line. Use
  for cross-token patterns (``cat /etc/shadow``, pipelines, URLs) and
  for "this command head touched this file" matches.

Audit review R2: an earlier ``argument_patterns`` kind matched the
argument portion regardless of the command head, so ``apt install``
tripped a systemd-service rule keyed on ``install`` and ``git show``
tripped a network-discovery rule keyed on ``show``. The head-match
short-circuit meant that branch only ever ran for an *unrelated* head,
so it produced only false positives; its one legitimate use (reading
``/etc/os-release`` via any command) moved to ``command_patterns``,
where cross-command matching belongs.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field

__all__ = ["TECHNIQUES", "TechniqueRule"]


@dataclass(frozen=True)
class TechniqueRule:
    """One MITRE ATT&CK detection rule."""

    id: str
    name: str
    description: str
    commands: tuple[str, ...] = ()
    command_patterns: tuple[re.Pattern[str], ...] = ()
    weight: int = field(default=5)
    persistence: bool = False

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("TechniqueRule.id must be non-empty")
        if self.weight < 1 or self.weight > 50:
            raise ValueError(
                f"TechniqueRule.weight must be in [1, 50], got {self.weight}",
            )

    def matches(self, command_line: str) -> bool:
        """Return True if this rule matches the given command line."""
        if not command_line.strip():
            return False
        try:
            tokens = shlex.split(command_line, posix=True)
        except ValueError:
            tokens = command_line.split()
        if not tokens:
            return False

        head = os.path.basename(tokens[0])
        if head in self.commands:
            return True

        return any(pat.search(command_line) for pat in self.command_patterns)


TECHNIQUES: tuple[TechniqueRule, ...] = (
    TechniqueRule(
        id="T1033",
        name="System Owner/User Discovery",
        description="Discover users on the host.",
        commands=("whoami", "id", "groups", "w", "who", "logname", "users"),
        weight=2,
    ),
    TechniqueRule(
        id="T1082",
        name="System Information Discovery",
        description="Gather kernel / OS / hostname information.",
        commands=(
            "uname",
            "hostname",
            "hostnamectl",
            "lsb_release",
            "uptime",
            "lscpu",
            "lshw",
            "dmidecode",
        ),
        command_patterns=(
            # Cross-command read of an OS-identity file (e.g. `cat
            # /etc/os-release`); a full-line match, not an arg match
            # (audit review R2a).
            re.compile(
                r"/etc/(os-release|issue|debian_version|redhat-release|lsb-release)",
            ),
        ),
        weight=2,
    ),
    TechniqueRule(
        id="T1083",
        name="File and Directory Discovery",
        description="Enumerate filesystem contents.",
        commands=("ls", "dir", "find", "tree", "locate", "stat"),
        weight=2,
    ),
    TechniqueRule(
        id="T1057",
        name="Process Discovery",
        description="List running processes.",
        commands=("ps", "top", "htop", "pgrep", "pidof"),
        weight=3,
    ),
    TechniqueRule(
        id="T1016",
        name="System Network Configuration Discovery",
        description="Inspect network interfaces and routing.",
        commands=("ifconfig", "iwconfig", "ip", "route", "arp"),
        # Audit review R2a: the head set already covers `ip addr`,
        # `ifconfig`, `route`, `arp` etc. The old argument_patterns
        # (\b(addr|link|route|neigh|show)\b) only ever ran for an
        # unrelated head, where it false-matched `git show`. Dropped.
        weight=3,
    ),
    TechniqueRule(
        id="T1049",
        name="System Network Connections Discovery",
        description="Inspect active network connections.",
        commands=("netstat", "ss", "lsof"),
        weight=3,
    ),
    TechniqueRule(
        id="T1018",
        name="Remote System Discovery",
        description="Enumerate other hosts reachable from this one.",
        commands=("ping", "fping", "traceroute", "tracepath", "mtr"),
        weight=3,
    ),
    TechniqueRule(
        id="T1046",
        name="Network Service Scanning",
        description="Active network scanning tools.",
        commands=(
            "nmap",
            "masscan",
            "zmap",
            "rustscan",
            "naabu",
            "unicornscan",
        ),
        weight=8,
    ),
    TechniqueRule(
        id="T1003",
        name="OS Credential Dumping",
        description="Read credential or secret files.",
        command_patterns=(
            re.compile(
                r"\b(cat|less|more|head|tail|nano|vi|vim|grep|awk|sed|strings)\b"
                r"[^\n]*"
                r"(/etc/shadow|/etc/gshadow|/etc/passwd|"
                r"/root/\.ssh|"
                r"\.bash_history|\.viminfo|\.lesshst|\.mysql_history)",
            ),
        ),
        weight=10,
    ),
    TechniqueRule(
        id="T1059.004",
        name="Unix Shell",
        description="Inline shell pipelines or reverse-shell patterns.",
        commands=("bash", "sh", "zsh", "dash", "ksh"),
        command_patterns=(
            # Audit L5: the gap quantifiers are bounded so neither pattern
            # re-anchors quadratically on attacker-controlled command text.
            # `[^|]*?` cannot cross a pipe (so each pipe segment is scanned
            # once), and `.{0,200}?` caps the reverse-shell gap to a line-
            # local window. Both stay match-equivalent on real pipelines.
            re.compile(
                r"\|[^|]*?\b(?:bash|sh|nc|netcat|ncat|python\d?|perl|ruby)\b",
            ),
            re.compile(
                r"\b(?:bash|sh)\s+-[ic].{0,200}?(?:exec|/dev/tcp|/dev/udp)",
            ),
        ),
        weight=6,
    ),
    TechniqueRule(
        id="T1105",
        name="Ingress Tool Transfer",
        description="Download tooling onto the host.",
        commands=("wget", "curl", "fetch", "aria2c", "axel"),
        command_patterns=(re.compile(r"\bhttps?://"),),
        weight=6,
    ),
    TechniqueRule(
        id="T1071",
        name="Application Layer Protocol",
        description="HTTP(s) C2 indicators (URLs pointing to binaries).",
        command_patterns=(
            re.compile(
                r"https?://\S+\.(?:bin|sh|elf|exe|so|tar|tgz|zip|py)",
                re.IGNORECASE,
            ),
        ),
        weight=5,
    ),
    TechniqueRule(
        id="T1053",
        name="Scheduled Task/Job",
        description="Crontab or at-job modifications.",
        commands=("crontab", "at", "batch"),
        command_patterns=(re.compile(r"/etc/cron|/var/spool/cron|/etc/at\.allow"),),
        weight=8,
        persistence=True,
    ),
    TechniqueRule(
        id="T1098",
        name="Account Manipulation",
        description="SSH key or password manipulation, sudoers edits.",
        commands=("passwd", "usermod", "chpasswd", "gpasswd", "visudo"),
        command_patterns=(
            # Audit review R2b: require a write/modify context near the
            # credential file. Read-only access (`cat /etc/shadow`, `grep
            # root /etc/sudoers`) is OS Credential Dumping (T1003), not
            # Account Manipulation, and must not flip persistence_attempted.
            # The {0,200} gap is bounded so the pattern stays linear (no
            # ReDoS), matching the T1059.004 hardening above.
            re.compile(
                r"(?:>>?|\btee\b|sed\s+-i|\bvim?\b|\bnano\b)"
                r"[^\n]{0,80}?"
                r"(?:authorized_keys|/etc/sudoers|/etc/shadow)",
            ),
        ),
        weight=9,
        persistence=True,
    ),
    TechniqueRule(
        id="T1136",
        name="Create Account",
        description="Create local accounts.",
        commands=("useradd", "adduser", "newusers"),
        weight=9,
        persistence=True,
    ),
    TechniqueRule(
        id="T1543",
        name="Create or Modify System Process",
        description="Install or enable system services.",
        commands=("systemctl", "service", "update-rc.d", "chkconfig"),
        # Audit review R2a: the head set covers the service-management
        # commands. The old argument_patterns (\b(enable|start|install)\b)
        # only ran for an unrelated head, so `apt|pip|make install` all
        # false-matched on the bare word `install`. Dropped; the
        # command_patterns below still catch direct unit-file writes.
        command_patterns=(re.compile(r"/etc/systemd/|/etc/init\.d/"),),
        weight=8,
        persistence=True,
    ),
    TechniqueRule(
        id="T1070",
        name="Indicator Removal on Host",
        description="Clear shell history or log files.",
        commands=("shred",),
        command_patterns=(
            re.compile(r"\bhistory\s+-c\b"),
            re.compile(r"\bunset\s+HISTFILE\b"),
            re.compile(r">\s*/var/log/|truncate.*\.log\b"),
            re.compile(r"\brm\b[^\n]*?/var/log"),
        ),
        weight=8,
    ),
    TechniqueRule(
        id="T1496",
        name="Resource Hijacking",
        description="Cryptominer process or pool indicators.",
        command_patterns=(
            re.compile(
                r"\b(xmrig|cpuminer|minerd|cgminer|ethminer|nicehash|kinsing|kdevtmpfsi)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"--coin\s+|--algo\s+|--pool\s+|stratum\+tcp://",
                re.IGNORECASE,
            ),
        ),
        weight=10,
    ),
)
