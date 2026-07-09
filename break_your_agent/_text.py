"""Shared text utilities: fullwidth normalization + the tiny directive grammar.

Both the (naive) mock model and the (defensive) sanitizer parse the SAME grammar
from the SAME place. That is deliberate: a real-world lesson is that your
defenses must understand the input at least as well as your model does. If the
model normalizes fullwidth unicode before "reading" instructions but your filter
does not, the filter is blind to exactly the payloads the model will obey.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

# A tool call the toy model can emit, expressed as a plain-text directive.
# name -> (compiled regex, list of argument names it captures)
_DIRECTIVES: Dict[str, Tuple[re.Pattern, Tuple[str, ...]]] = {
    "run_cmd": (re.compile(r"^\s*RUN:\s*(.+?)\s*$", re.I), ("cmd",)),
    "fetch_url": (re.compile(r"^\s*FETCH:\s*(\S+)\s*$", re.I), ("url",)),
    "read_note": (re.compile(r"^\s*READNOTE:\s*(\S+)\s*$", re.I), ("name",)),
    "send_message": (
        re.compile(r"^\s*SEND:\s*([^|]+?)\s*\|\s*(.+?)\s*$", re.I),
        ("to", "body"),
    ),
}


def normalize_fullwidth(text: str) -> str:
    """Map fullwidth / ideographic-space characters back to ASCII.

    Covers U+FF01..U+FF5E (fullwidth ASCII, incl. the DSML-style delimiters
    ｜ U+FF5C, ＜ U+FF1C, ＞ U+FF1E) and U+3000 (ideographic space).
    """
    out: List[str] = []
    for ch in text:
        o = ord(ch)
        if 0xFF01 <= o <= 0xFF5E:
            out.append(chr(o - 0xFEE0))
        elif o == 0x3000:
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


def parse_line(line: str) -> Optional[Tuple[str, Dict[str, str]]]:
    """Parse a single line into (tool_name, args) if it is a directive."""
    for name, (pattern, arg_names) in _DIRECTIVES.items():
        m = pattern.match(line)
        if m:
            args = {k: v for k, v in zip(arg_names, m.groups())}
            return name, args
    return None


def parse_directives(text: str, *, normalize: bool = True) -> List[Tuple[str, Dict[str, str]]]:
    """Extract every directive from a block of text, in order of appearance."""
    if normalize:
        text = normalize_fullwidth(text)
    found: List[Tuple[str, Dict[str, str]]] = []
    for line in text.splitlines():
        parsed = parse_line(line)
        if parsed is not None:
            found.append(parsed)
    return found


def strip_directives(text: str, *, normalize_first: bool = True) -> str:
    """Neutralize any lines that look like directives.

    This is the core of the trust-tiering / output-sanitization defense: content
    that arrives from an untrusted channel (a fetched page, a note someone else
    wrote, a tool result) must never be interpretable as an *instruction*.

    ``normalize_first`` toggles the exact bug attack #6 exploits: a filter that
    matches only ASCII will happily pass a fullwidth ``ＦＥＴＣＨ：`` that the model
    later normalizes and obeys.
    """
    out: List[str] = []
    for line in text.splitlines():
        probe = normalize_fullwidth(line) if normalize_first else line
        if parse_line(probe) is not None:
            out.append("[neutralized-directive]")
        else:
            out.append(line)
    return "\n".join(out)
