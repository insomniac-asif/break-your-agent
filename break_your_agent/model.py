"""Pluggable "model" callables for the agent loop.

The agent doesn't care what a model *is* — only that it maps a message list to a
:class:`ModelResponse` (either one tool call or a final answer). This is what
makes the whole lab runnable with no GPU: the default model is a deterministic
script of *gullible* behavior.

``MockModel`` is intentionally naive in one specific, realistic way: it obeys
imperative directives found *anywhere* in its context — including the output of
tools — and it normalizes fullwidth unicode before reading them. That single
design flaw ("data is treated as instructions") is what every attack here
exploits, and it mirrors how real LLM agents actually fail.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ._text import normalize_fullwidth, parse_directives

# Placeholder the model resolves to the most recently read note. Lets an
# attacker script a two-step "read secret, then leak it" chain.
LAST_NOTE = "{{last_note}}"


@dataclass
class ToolCallRequest:
    name: str
    args: Dict[str, str]


@dataclass
class ModelResponse:
    tool_call: Optional[ToolCallRequest] = None
    final: Optional[str] = None


def _canonical(args: Dict[str, str]) -> Tuple[Tuple[str, str], ...]:
    return tuple(sorted((k, str(v)) for k, v in args.items()))


class MockModel:
    """A deterministic, deliberately-gullible agent brain.

    Each turn it:
      1. rebuilds the set of tool calls it has already made (from history),
      2. re-reads *every* user/tool message for directives (normalizing unicode),
      3. resolves ``{{last_note}}`` against the most recent note it has read,
      4. emits the first directive it has not yet executed, else finishes.
    """

    def __call__(self, messages: List[dict], ctx: dict) -> ModelResponse:
        executed = set()
        last_note = ""
        for m in messages:
            call = m.get("tool_call")
            if call:
                executed.add((call["name"], _canonical(call["args"])))
            if m.get("role") == "tool" and m.get("name") == "read_note":
                last_note = m.get("content", "")

        for m in messages:
            if m.get("role") not in ("user", "tool"):
                continue
            for name, args in parse_directives(m.get("content", "")):
                args = {
                    k: v.replace(LAST_NOTE, last_note) if last_note else v
                    for k, v in args.items()
                }
                key = (name, _canonical(args))
                if key in executed:
                    continue
                return ModelResponse(tool_call=ToolCallRequest(name=name, args=args))

        return ModelResponse(final="done — nothing left to do.")


class OllamaModel:
    """Optional real-model adapter using Ollama's NATIVE function-calling.

    It advertises the agent's sandboxed tools as function schemas and lets a real
    local model decide which to call — exactly how a production tool-calling agent
    works. That's what makes the live scorecard meaningful: it measures whether an
    actual model emits a *malicious* tool call when attacker-controlled text tells
    it to, and whether the architectural defenses stop it regardless.

        from break_your_agent.model import OllamaModel
        model = OllamaModel(model="llama3.2:3b")

    Uses only the standard library (urllib) — no extra dependencies. Needs
    ``ollama serve`` on localhost and a model that supports tools (llama3.2,
    qwen2.5, mistral-nemo, ...). Not used by the test suite (tests use MockModel).
    """

    TOOLS = [
        {"type": "function", "function": {
            "name": "read_note", "description": "Return the contents of a saved note.",
            "parameters": {"type": "object",
                           "properties": {"name": {"type": "string"}}, "required": ["name"]}}},
        {"type": "function", "function": {
            "name": "run_cmd", "description": "Run a shell command (privileged).",
            "parameters": {"type": "object",
                           "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}}},
        {"type": "function", "function": {
            "name": "fetch_url", "description": "Fetch a web page by URL.",
            "parameters": {"type": "object",
                           "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
        {"type": "function", "function": {
            "name": "send_message", "description": "Send a message to a recipient.",
            "parameters": {"type": "object",
                           "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
                           "required": ["to", "body"]}}},
    ]

    def __init__(self, model: str = "llama3.2:3b", host: str = "http://localhost:11434",
                 temperature: float = 0.0):
        self.model = model
        self.host = host.rstrip("/")
        self.temperature = temperature

    def _to_ollama(self, messages: List[dict]) -> List[dict]:
        """Translate the agent's message log into Ollama's native chat format."""
        out: List[dict] = []
        for m in messages:
            role = m.get("role")
            if role in ("system", "user"):
                out.append({"role": role, "content": m.get("content", "")})
            elif role == "assistant":
                call = m.get("tool_call")
                if call:
                    out.append({"role": "assistant", "content": m.get("content", ""),
                                "tool_calls": [{"function": {"name": call["name"],
                                                             "arguments": call["args"]}}]})
                else:
                    out.append({"role": "assistant", "content": m.get("content", "")})
            elif role == "tool":
                out.append({"role": "tool", "content": m.get("content", ""),
                            "tool_name": m.get("name", "")})
        return out

    def __call__(self, messages: List[dict], ctx: dict) -> ModelResponse:
        import json
        import urllib.request

        payload = json.dumps({
            "model": self.model,
            "messages": self._to_ollama(messages),
            "tools": self.TOOLS,
            "stream": False,
            "options": {"temperature": self.temperature},
        }).encode()
        req = urllib.request.Request(
            f"{self.host}/api/chat", data=payload, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
        msg = data.get("message", {}) or {}
        calls = msg.get("tool_calls") or []
        if calls:
            fn = (calls[0] or {}).get("function", {}) or {}
            args = fn.get("arguments", {}) or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {}
            args = {k: str(v) for k, v in args.items()}
            return ModelResponse(tool_call=ToolCallRequest(name=fn.get("name", ""), args=args))
        return ModelResponse(final=(msg.get("content", "") or "done.").strip())
