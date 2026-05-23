"""MITRE ATT&CK technique detection rules.

The rule set is deliberately conservative — every entry has a stable
ATT&CK technique identifier so threat-intel consumers can correlate
Anglerfish observations with other sources. Adding a new rule means
adding a new :class:`TechniqueRule` here; the scorer pulls in
:data:`TECHNIQUES` unconditionally.

Three kinds of matches are supported per rule:

* ``commands`` — exact command-name match against the first token of
  the command line (after :mod:`shlex` parsing). Absolute paths are
  collapsed to the basename so ``/usr/bin/whoami`` and ``whoami`` both
  match the rule.
* ``argument_patterns`` — regex applied to the argument portion of
  the command (everything after the first token).
* ``command_patterns`` — regex applied to the full command line. Use
  for cross-token patterns (``cat /etc/shadow``, pipelines, URLs).
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
    argument_patterns: tuple[re.Pattern[str], ...] = ()
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

        if self.argument_patterns:
            args_text = " ".join(tokens[1:])
            if any(pat.search(args_text) for pat in self.argument_patterns):
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
        argument_patterns=(
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
        argument_patterns=(re.compile(r"\b(addr|link|route|neigh|show)\b"),),
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
            re.compile(
                r"\|.*?\b(?:bash|sh|nc|netcat|ncat|python\d?|perl|ruby)\b",
            ),
            re.compile(
                r"\b(?:bash|sh)\s+-[ic].*?(?:exec|/dev/tcp|/dev/udp)",
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
        commands=("passwd", "usermod", "chpasswd", "gpasswd"),
        command_patterns=(re.compile(r"authorized_keys|/etc/sudoers|/etc/shadow"),),
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
        argument_patterns=(re.compile(r"\b(enable|start|install)\b"),),
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
