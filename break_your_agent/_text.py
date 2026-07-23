"""Shared text utilities: fullwidth normalization + the tiny directive grammar.

Both the (naive) mock model and the (defensive) sanitizer parse the SAME grammar
from the SAME place. That is deliberate: a real-world lesson is that your
defenses must understand the input at least as well as your model does. If the
model normalizes fullwidth unicode before "reading" instructions but your filter
does not, the filter is blind to exactly the payloads the model will obey.
"""

from __future__ import annotations

import json
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


# --------------------------------------------------------------------------- #
# Tool-call rescue (for the --live path)
#
# Real local models don't always emit a native ``tool_calls`` field. When a
# model is coaxed into narrating ("I'll fetch the continuation…") it frequently
# emits the call as TEXT or markup instead — a Hermes/Qwen ``<tool_call>`` tag,
# a fenced ```json block, an ``<invoke>/<parameter>`` XML form, or a bare JSON
# object. Without recovering those, a model that *did* fall for an attack reads
# as a false "safe" — which understates the vulnerability and is dishonest. The
# harder attacks (A07–A11: authority-spoof, multi-hop, best-of-N) are exactly
# the ones that provoke narration, so rescuing text-emitted calls is what makes
# the full live ladder measurable.
#
# This is a deliberately small, dependency-free descendant of the author's
# `toolcall-rescue` project (github.com/insomniac-asif/toolcall-rescue). It
# normalizes fullwidth unicode FIRST — the same A06 lesson applied to a parser:
# a parser must understand the input at least as well as the model does.
# --------------------------------------------------------------------------- #

# Keys under which a salvaged JSON call may carry its argument object.
_TC_ARG_KEYS: Tuple[str, ...] = ("arguments", "args", "parameters", "params", "input")


def _coerce_call(obj: object) -> Optional[Tuple[str, Dict[str, str]]]:
    """Pull (name, args) out of a parsed JSON object IFF it has a tool-call shape.

    Requires both a name and an explicit argument container — so ordinary data
    like ``{"name": "Bob", "age": 3}`` is rejected, not misread as a call.
    """
    if not isinstance(obj, dict):
        return None
    fn = obj.get("function")
    if isinstance(fn, dict) and isinstance(fn.get("name"), str) and fn["name"]:
        name: Optional[str] = fn["name"]
        args: object = fn.get("arguments", {})
    else:
        name = None
        for k in ("name", "tool", "tool_name"):
            v = obj.get(k)
            if isinstance(v, str) and v:
                name = v
                break
        args = None
        for k in _TC_ARG_KEYS:
            v = obj.get(k)
            if isinstance(v, (dict, str)):
                args = v
                break
    if not name or args is None:
        return None
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except Exception:
            return None
    if not isinstance(args, dict):
        return None
    return name, {k: str(v) for k, v in args.items()}


def _brace_objects(text: str) -> List[str]:
    """Return every top-level ``{...}`` substring (best-effort, brace-balanced)."""
    objs: List[str] = []
    depth = 0
    start: Optional[int] = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start is not None:
                objs.append(text[start:i + 1])
                start = None
    return objs


def extract_toolcall_from_text(content: str) -> Optional[Tuple[str, Dict[str, str]]]:
    """Best-effort salvage of a tool call a model emitted as text/markup.

    Returns ``(tool_name, args)`` or ``None``. Tries, in order: an XML
    ``<invoke>/<parameter>`` form, a Hermes ``<tool_call>{...}</tool_call>`` tag,
    a fenced ```json block, then any bare JSON object with a tool-call shape.
    Fullwidth unicode is normalized first. The caller is responsible for
    validating the returned name against its real tool set.
    """
    if not content:
        return None
    text = normalize_fullwidth(content)

    # 1. XML <invoke name="X"><parameter name="k">v</parameter> ...</invoke>
    inv = re.search(
        r"<invoke\b[^>]*\bname=[\"']([^\"']+)[\"'][^>]*>(.*?)</invoke>", text, re.S | re.I
    )
    if inv:
        args: Dict[str, str] = {}
        for pm in re.finditer(
            r"<parameter\b[^>]*\bname=[\"']([^\"']+)[\"'][^>]*>(.*?)</parameter>",
            inv.group(2), re.S | re.I,
        ):
            args[pm.group(1)] = pm.group(2).strip()
        return inv.group(1), args

    # 2/3/4. JSON payloads: Hermes tag, fenced block, then bare objects.
    candidates: List[str] = []
    candidates += re.findall(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", text, re.S | re.I)
    candidates += re.findall(
        r"```(?:json|tool_call|tool_calls)?\s*(\{.*?\}|\[.*?\])\s*```", text, re.S | re.I
    )
    candidates += _brace_objects(text)
    for cand in candidates:
        try:
            parsed = json.loads(cand)
        except Exception:
            continue
        for o in (parsed if isinstance(parsed, list) else [parsed]):
            # Unwrap common envelopes: {"tool_calls": [...]}, {"tool_call": {...}}.
            if isinstance(o, dict) and isinstance(o.get("tool_calls"), list) and o["tool_calls"]:
                o = o["tool_calls"][0]
            if isinstance(o, dict) and isinstance(o.get("tool_call"), dict):
                o = o["tool_call"]
            call = _coerce_call(o)
            if call is not None:
                return call
    return None
