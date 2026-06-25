"""MITRE ATT&CK technique mapping for captured sessions.

Maps the observable behaviour of a session -- its commands, credential attempts,
and bait interactions -- onto MITRE ATT&CK technique IDs, producing the
``mitre_techniques`` field the core leaves empty. This is rule-based and
transparent (like the tool-signature weak labels): a curated set of regex /
signal rules, each tied to a specific technique and tactic, so every mapping is
explainable and auditable for the threat-intel report.

Coverage focuses on what an SSH honeypot can actually observe: Credential Access
(brute force, reading planted secrets), Discovery (enumeration), Execution,
Persistence (authorized_keys, cron, accounts), Defense Evasion (history wipe,
firewall tampering), Command-and-Control / Ingress Tool Transfer, Impact
(cryptomining), and Exfiltration (bait copy/exfil). Bait interactions are mapped
explicitly -- reading a planted private key is T1552.004 whether or not the
command text reveals it -- which is one of the payoffs of the core's new bait
subsystem.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .ingest import ProductionSession

__all__ = ["Technique", "TechniqueHit", "map_mitre", "map_mitre_ids"]


@dataclass(frozen=True)
class Technique:
    """A MITRE ATT&CK technique.

    Attributes:
        id: Technique ID (e.g. ``T1110`` or sub-technique ``T1098.004``).
        name: Technique name.
        tactic: The ATT&CK tactic (kill-chain phase) it serves.
    """

    id: str
    name: str
    tactic: str


@dataclass
class TechniqueHit:
    """A matched technique plus the evidence that triggered it."""

    technique: Technique
    evidence: str


# -- Technique catalogue (the subset an SSH honeypot can observe) ------------

EXECUTION_SHELL = Technique("T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution")
INGRESS_TOOL = Technique("T1105", "Ingress Tool Transfer", "Command and Control")
PERMS_MOD = Technique("T1222", "File and Directory Permissions Modification", "Defense Evasion")
SYS_INFO = Technique("T1082", "System Information Discovery", "Discovery")
USER_DISCOVERY = Technique("T1033", "System Owner/User Discovery", "Discovery")
FILE_DISCOVERY = Technique("T1083", "File and Directory Discovery", "Discovery")
ACCOUNT_DISCOVERY = Technique("T1087", "Account Discovery", "Discovery")
NET_DISCOVERY = Technique("T1046", "Network Service Discovery", "Discovery")
SSH_KEYS = Technique("T1098.004", "Account Manipulation: SSH Authorized Keys", "Persistence")
CRON = Technique("T1053.003", "Scheduled Task/Job: Cron", "Persistence")
CREATE_ACCOUNT = Technique("T1136.001", "Create Account: Local Account", "Persistence")
CLEAR_HISTORY = Technique("T1070.003", "Indicator Removal: Clear Command History", "Defense Evasion")
IMPAIR_DEFENSES = Technique("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion")
RESOURCE_HIJACK = Technique("T1496", "Resource Hijacking", "Impact")
SUDO = Technique("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation")
CREDS_IN_FILES = Technique("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access")
PRIVATE_KEYS = Technique("T1552.004", "Unsecured Credentials: Private Keys", "Credential Access")
ETC_SHADOW = Technique("T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", "Credential Access")
BRUTE_FORCE = Technique("T1110", "Brute Force", "Credential Access")
VALID_ACCOUNTS = Technique("T1078", "Valid Accounts", "Initial Access")
EXFIL_C2 = Technique("T1041", "Exfiltration Over C2 Channel", "Exfiltration")


# Regex rules over the joined command text. Order is for readability only;
# results are de-duplicated and tactic-ordered.
_COMMAND_RULES: list[tuple[re.Pattern[str], Technique]] = [
    (re.compile(r"\b(?:wget|curl|tftp|ftpget|scp)\b", re.I), INGRESS_TOOL),
    (re.compile(r"\bchmod\b", re.I), PERMS_MOD),
    (re.compile(r"\b(?:uname|lscpu|nproc|lsb_release|hostnamectl)\b|/proc/(?:cpuinfo|version)", re.I), SYS_INFO),
    (re.compile(r"\b(?:whoami|id)\b", re.I), USER_DISCOVERY),
    (re.compile(r"\b(?:ls|find|locate)\b", re.I), FILE_DISCOVERY),
    (re.compile(r"/etc/passwd", re.I), ACCOUNT_DISCOVERY),
    (re.compile(r"\b(?:netstat|ss|nmap|arp|ifconfig|ip\s+a)\b", re.I), NET_DISCOVERY),
    (re.compile(r"authorized_keys", re.I), SSH_KEYS),
    (re.compile(r"\bcrontab\b|/etc/cron", re.I), CRON),
    (re.compile(r"\b(?:useradd|adduser)\b", re.I), CREATE_ACCOUNT),
    (re.compile(r"history\s+-c|unset\s+HISTFILE|>\s*~?/?\.bash_history", re.I), CLEAR_HISTORY),
    (re.compile(r"iptables\s+-F|ufw\s+disable|\bchattr\b|setenforce\s+0", re.I), IMPAIR_DEFENSES),
    (re.compile(r"xmrig|minerd|cpuminer|stratum\+tcp|--donate-level", re.I), RESOURCE_HIJACK),
    (re.compile(r"\bsudo\b|\bsu\s", re.I), SUDO),
    (re.compile(r"\.env\b", re.I), CREDS_IN_FILES),
    (re.compile(r"/etc/shadow", re.I), ETC_SHADOW),
]

# Map a bait type to the technique its access implies.
_BAIT_TYPE_TECHNIQUE: dict[str, Technique] = {
    "private_key": PRIVATE_KEYS,
    "shadow": ETC_SHADOW,
    "env_file": CREDS_IN_FILES,
    "credential": CREDS_IN_FILES,
    "config": CREDS_IN_FILES,
}

#: ATT&CK tactic order (kill-chain phase) for stable, readable output.
_TACTIC_ORDER: dict[str, int] = {
    "Initial Access": 0,
    "Execution": 1,
    "Persistence": 2,
    "Privilege Escalation": 3,
    "Defense Evasion": 4,
    "Credential Access": 5,
    "Discovery": 6,
    "Command and Control": 7,
    "Exfiltration": 8,
    "Impact": 9,
}


def map_mitre(prod: ProductionSession) -> list[TechniqueHit]:
    """Map a session to ATT&CK technique hits with evidence.

    Returns a de-duplicated, tactic-ordered list of :class:`TechniqueHit`.
    """
    hits: dict[str, TechniqueHit] = {}

    def add(tech: Technique, evidence: str) -> None:
        hits.setdefault(tech.id, TechniqueHit(tech, evidence))

    raws = prod.session.raw_commands()
    blob = "\n".join(raws)

    if raws:
        add(EXECUTION_SHELL, "shell commands executed")
    for pattern, tech in _COMMAND_RULES:
        match = pattern.search(blob)
        if match:
            add(tech, f"command matched /{pattern.pattern[:40]}/ ({match.group(0)!r})")

    # Credential-access signals from auth attempts.
    distinct_creds = {a.credential for a in prod.auth_attempts}
    if len(prod.auth_attempts) >= 3 and len(distinct_creds) >= 2:
        add(BRUTE_FORCE, f"{len(prod.auth_attempts)} credential attempts")
    if any(a.success for a in prod.auth_attempts):
        add(VALID_ACCOUNTS, "accepted credential (honeypot grants access)")

    # Bait interactions → credential-access / exfiltration techniques.
    for bait in prod.bait_events:
        tech = _BAIT_TYPE_TECHNIQUE.get(bait.bait_type)
        if tech is not None:
            add(tech, f"bait {bait.bait_type} {bait.access_type}")
        if bait.access_type == "exfil_attempt":
            add(EXFIL_C2, f"exfil attempt on {bait.bait_type} bait")

    return sorted(
        hits.values(),
        key=lambda h: (_TACTIC_ORDER.get(h.technique.tactic, 99), h.technique.id),
    )


def map_mitre_ids(prod: ProductionSession) -> list[str]:
    """Convenience: just the ordered technique IDs (the ``mitre_techniques`` column)."""
    return [hit.technique.id for hit in map_mitre(prod)]
