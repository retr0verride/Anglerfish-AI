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

import unicodedata

__all__ = [
    "TRUNCATION_MARKER",
    "cap_output",
    "normalise_for_scan",
    "sanitize_command",
    "strip_control_chars",
]


TRUNCATION_MARKER = "\n[input truncated]"

_ALLOWED_CONTROL_CHARS = frozenset({"\t", "\n"})


def normalise_for_scan(text: str) -> str:
    """Canonicalise text for the Stage 1 defense regex scan (audit H2).

    The defense patterns are ASCII literals with ``\\b`` word boundaries,
    so a single invisible, compatibility-form, or combining character
    spliced into a token defeats a match. Three steps close that:

    * **NFKD** decomposition folds compatibility forms (fullwidth Latin,
      ligatures, circled/super/subscript letters) onto their ASCII
      equivalents and splits precomposed accented letters into a base
      letter plus combining marks.
    * All Unicode combining marks (categories ``Mn`` / ``Mc`` / ``Me``)
      are then removed, so both a precomposed accent (``ignòre``) and a
      free combining mark spliced under a letter (``ig`` + U+0300 +
      ``nore``) fold back to the bare ASCII token.
    * All Unicode ``Cf`` (format) characters are removed: the zero-width
      space / joiner / non-joiner (U+200B/C/D), word joiner (U+2060),
      BOM (U+FEFF), soft hyphen (U+00AD), and the bidi marks.

    Used only to build the scan target; the original attacker bytes are
    preserved in the prompt and the captured session record. This folds
    Latin diacritics but NOT cross-script confusable homoglyphs (Cyrillic
    small-a U+0430 stays distinct from Latin ``a``); that residual is
    documented in ``docs/THREAT_MODEL.md``.
    """
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(
        ch
        for ch in decomposed
        if unicodedata.category(ch)[0] != "M" and unicodedata.category(ch) != "Cf"
    )


def strip_control_chars(text: str, *, allowed: frozenset[str] = _ALLOWED_CONTROL_CHARS) -> str:
    """Drop C0 control characters (< 0x20) and DEL (0x7F), keeping ``allowed``.

    ``allowed`` defaults to tab and LF. This is the single source of truth
    for the control-character filter, shared by the bridge's command
    sanitiser (inbound) and the lure's outbound text filter, so the two
    cannot drift apart.
    """
    return "".join(ch for ch in text if ch in allowed or (ord(ch) >= 0x20 and ord(ch) != 0x7F))


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
    cleaned = strip_control_chars(normalised)

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
