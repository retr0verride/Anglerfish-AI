"""Input sanitisation and output capping for attacker-controlled content.

The bridge never trusts an attacker's command string verbatim. Two
operations are applied:

* :func:`sanitize_command` strips C0 control characters (except tab and
  LF), normalises line endings, and truncates to a configured cap. It
  produces a string safe to embed in an LLM prompt.
* :func:`cap_output` caps the LLM response to a configured length.
  Truncation is silent — the LLM is not informed that its output was
  cut, so it cannot use the cap as a signal in its reply.
"""

from __future__ import annotations

__all__ = ["TRUNCATION_MARKER", "cap_output", "sanitize_command"]


TRUNCATION_MARKER = "\n[input truncated]"

_ALLOWED_CONTROL_CHARS = frozenset({"\t", "\n"})


def sanitize_command(raw: str, *, max_chars: int) -> str:
    """Return a prompt-safe version of an attacker-supplied command.

    Steps applied, in order:

    1. ``TypeError`` if ``raw`` is not a :class:`str` — prevents bytes
       or :data:`None` from being smuggled into the prompt template.
    2. CR/LF and bare CR line endings are normalised to bare LF.
    3. All C0 control characters except tab and LF are dropped, as is
       DEL (0x7F).
    4. The result is truncated to ``max_chars`` with a visible marker
       appended so the LLM can see input was cut.

    The output is always a :class:`str` of length at most
    ``max_chars + len(TRUNCATION_MARKER)``.
    """
    if not isinstance(raw, str):
        raise TypeError(
            f"sanitize_command expected str, got {type(raw).__name__}",
        )
    if max_chars <= 0:
        raise ValueError(f"max_chars must be positive, got {max_chars}")

    normalised = raw.replace("\r\n", "\n").replace("\r", "\n")
    cleaned_chars: list[str] = []
    for ch in normalised:
        if ch in _ALLOWED_CONTROL_CHARS:
            cleaned_chars.append(ch)
            continue
        code = ord(ch)
        if code < 0x20 or code == 0x7F:
            continue
        cleaned_chars.append(ch)
    cleaned = "".join(cleaned_chars)

    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars] + TRUNCATION_MARKER
    return cleaned


def cap_output(raw: str, *, max_chars: int) -> str:
    """Cap a model-produced response to ``max_chars`` characters.

    Strips trailing whitespace. The cap is applied silently — no marker
    is appended — because the attacker should not be able to infer the
    output limit from the response.
    """
    if not isinstance(raw, str):
        raise TypeError(
            f"cap_output expected str, got {type(raw).__name__}",
        )
    if max_chars <= 0:
        raise ValueError(f"max_chars must be positive, got {max_chars}")
    return raw[:max_chars].rstrip()
