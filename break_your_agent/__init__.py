"""break-your-agent — a hands-on lab of tool-calling agent attacks & defenses.

Educational / defensive use only. Everything is sandboxed: no real commands run,
no real network calls are made.
"""

from __future__ import annotations

from .agent import Agent, AgentResult, ToolCall
from .model import MockModel, ModelResponse, OllamaModel, ToolCallRequest
from .policy import DefensePolicy, NullPolicy
from .tools import DEMO_SECRET, OWNER_ID, Environment

__version__ = "0.1.0"

__all__ = [
    "Agent",
    "AgentResult",
    "ToolCall",
    "MockModel",
    "OllamaModel",
    "ModelResponse",
    "ToolCallRequest",
    "DefensePolicy",
    "NullPolicy",
    "Environment",
    "DEMO_SECRET",
    "OWNER_ID",
    "__version__",
]
