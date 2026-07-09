"""Defense policies — the layers that turn PWNED into BLOCKED.

A policy has two hooks the agent calls:

* ``check(name, args, ctx) -> reason|None`` — runs *before* a tool executes.
  Return a string to block the call (allow/deny gating, owner-approval sentinel,
  per-resource ACL, argument DLP). Return ``None`` to allow it.
* ``sanitize(name, output, trust) -> str`` — runs on a tool's result *before* it
  re-enters the model's context (trust-tiering + output sanitization).

``NullPolicy`` is the undefended baseline. ``DefensePolicy`` composes independent
layers so each attack can be shown blocked by *only* its primary defense, and so
you can see which layers are load-bearing for which attack.
"""

from __future__ import annotations

import re
from typing import Dict, FrozenSet, Optional

from ._text import strip_directives
from .tools import OWNER_ID, PRIVILEGED_TOOLS

# High-entropy secret shapes we refuse to let leave via tool arguments.
_SECRET_RE = re.compile(r"sk-[A-Za-z0-9][A-Za-z0-9_-]{5,}")

# In-band tokens an attacker might forge to fake authorization. Approval is
# strictly out-of-band (ctx), so these are always stripped from content.
_CONTROL_TOKENS = ("OWNER_APPROVAL_GRANTED", "[[APPROVED]]", "approved by owner")


class NullPolicy:
    """No defenses. The vulnerable baseline."""

    name = "undefended"

    def check(self, name: str, args: Dict[str, str], ctx: dict) -> Optional[str]:
        return None

    def sanitize(self, name: str, output: str, trust: str) -> str:
        return output


class DefensePolicy:
    """Composable defenses. Toggle layers individually or use :meth:`hardened`."""

    name = "defended"

    def __init__(
        self,
        *,
        allowed_tools: Optional[FrozenSet[str]] = None,
        gate_privileged: bool = False,
        acl: bool = False,
        arg_dlp: bool = False,
        trust_tiering: bool = False,
        normalize_first: bool = True,
        owner_only_notes: FrozenSet[str] = frozenset({"apikey"}),
        owner_id: str = OWNER_ID,
        max_output: int = 4000,
    ) -> None:
        self.allowed_tools = allowed_tools
        self.gate_privileged = gate_privileged
        self.acl = acl
        self.arg_dlp = arg_dlp
        self.trust_tiering = trust_tiering
        self.normalize_first = normalize_first
        self.owner_only_notes = owner_only_notes
        self.owner_id = owner_id
        self.max_output = max_output

    @classmethod
    def hardened(cls) -> "DefensePolicy":
        return cls(
            gate_privileged=True,
            acl=True,
            arg_dlp=True,
            trust_tiering=True,
            normalize_first=True,
        )

    # --- pre-execution gating -------------------------------------------
    def check(self, name: str, args: Dict[str, str], ctx: dict) -> Optional[str]:
        # 1. tool allow/deny gating
        if self.allowed_tools is not None and name not in self.allowed_tools:
            return f"TOOL_NOT_ALLOWED:{name}"

        # 2. owner-approval sentinel for mutating tools (approval is out-of-band)
        if self.gate_privileged and name in PRIVILEGED_TOOLS:
            if not ctx.get("owner_approved", False):
                return f"NEEDS_OWNER_APPROVAL:{name}"

        # 3. per-resource ACL (confused-deputy prevention)
        if self.acl and name == "read_note":
            note = args.get("name", "")
            if note in self.owner_only_notes and ctx.get("user_id") != self.owner_id:
                return f"ACL_DENIED:{note}"

        # 4. argument DLP (block secret material leaving via any tool arg)
        if self.arg_dlp:
            for value in args.values():
                if _SECRET_RE.search(str(value)):
                    return "EXFIL_BLOCKED:secret-in-argument"

        return None

    # --- post-execution sanitization ------------------------------------
    def sanitize(self, name: str, output: str, trust: str) -> str:
        if not self.trust_tiering or trust != "untrusted":
            return output
        cleaned = strip_directives(output, normalize_first=self.normalize_first)
        for token in _CONTROL_TOKENS:
            cleaned = cleaned.replace(token, "[neutralized-control-token]")
        return cleaned[: self.max_output]
