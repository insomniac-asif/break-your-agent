"""The sandboxed tool surface and the world the agent acts on.

None of these tools do anything dangerous in reality:
- ``run_cmd`` never spawns a process; it echoes the command back.
- ``fetch_url`` returns canned fixture content, never touching the network.
- ``send_message`` records the message in a list instead of sending it.

The *lesson* is not that these specific calls are dangerous — it is that an
attacker who can steer *which* tool runs with *which* arguments has already won
against a real agent wired to real side effects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

# A believable-looking but entirely fake credential used across the demos.
DEMO_SECRET = "sk-DEMO-1a2b3c4d5e6f7g8h"

OWNER_ID = "owner-1"


@dataclass
class SentMessage:
    to: str
    body: str


@dataclass
class Environment:
    """A fresh, isolated world for a single scenario run."""

    notes: Dict[str, str] = field(default_factory=dict)
    note_owner: Dict[str, Optional[str]] = field(default_factory=dict)
    fixtures: Dict[str, str] = field(default_factory=dict)
    sent: List[SentMessage] = field(default_factory=list)
    fetched: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)

    # --- tools -----------------------------------------------------------
    def read_note(self, name: str, _ctx: dict) -> str:
        return self.notes.get(name, f"[no note named {name!r}]")

    def run_cmd(self, cmd: str, _ctx: dict) -> str:
        # SANDBOX: we never execute anything. We only record + echo.
        self.commands.append(cmd)
        return f"[sandbox echo] {cmd}"

    def fetch_url(self, url: str, _ctx: dict) -> str:
        self.fetched.append(url)
        return self.fixtures.get(url, f"[unreachable: {url}]")

    def send_message(self, to: str, body: str, _ctx: dict) -> str:
        self.sent.append(SentMessage(to=to, body=body))
        return f"[queued message to {to}]"

    def registry(self) -> Dict[str, Callable[..., str]]:
        return {
            "read_note": self.read_note,
            "run_cmd": self.run_cmd,
            "fetch_url": self.fetch_url,
            "send_message": self.send_message,
        }


# Tools that cause side effects / spend privilege. Used by the approval-sentinel
# defense. read_note and fetch_url are "read-ish" and not gated by approval.
PRIVILEGED_TOOLS = frozenset({"run_cmd", "send_message"})

# Tool schema advertised to a real model (also handy documentation).
TOOL_SCHEMA = {
    "read_note": "read_note(name): return the contents of a saved note.",
    "run_cmd": "run_cmd(cmd): run a shell command (SANDBOXED: echo only).",
    "fetch_url": "fetch_url(url): fetch a web page (SANDBOXED: fixtures only).",
    "send_message": "send_message(to, body): send a message to a recipient.",
}
