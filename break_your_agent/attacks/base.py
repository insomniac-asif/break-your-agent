"""Shared scaffolding for attack scenarios."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from ..agent import Agent, AgentResult
from ..model import MockModel
from ..policy import DefensePolicy, NullPolicy
from ..tools import Environment

# A scenario builder returns (env, ctx, user_message).
Builder = Callable[[], Tuple[Environment, dict, str]]

# A scenario runner takes a policy, runs the agent, returns (result, env, ctx).
Runner = Callable[[object], Tuple[AgentResult, Environment, dict]]


@dataclass
class Attack:
    id: str
    title: str
    summary: str
    primary_defense: str  # human label of the defense that stops it
    build: Builder
    dangerous: Callable[[AgentResult, Environment, dict], bool]
    minimal_policy: DefensePolicy  # smallest policy that should block it

    def run(self, policy, model=None) -> Tuple[AgentResult, Environment, dict]:
        env, ctx, user_message = self.build()
        # Default to the deterministic mock; pass a real model (e.g. OllamaModel)
        # to watch an actual local model face the same scenario.
        agent = Agent(model=model or MockModel(), env=env, policy=policy)
        result = agent.run(user_message, ctx)
        return result, env, ctx

    def is_pwned(self, policy, model=None) -> bool:
        result, env, ctx = self.run(policy, model=model)
        return self.dangerous(result, env, ctx)


def run_attack(attack: Attack, policy) -> bool:
    """Convenience: True if the dangerous outcome occurred under ``policy``."""
    return attack.is_pwned(policy)


UNDEFENDED = NullPolicy()
HARDENED = DefensePolicy.hardened()
