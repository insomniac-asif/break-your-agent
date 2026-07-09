"""The graded attack ladder.

Each attack module exposes a single :class:`Attack` instance describing:
  * how to build a fresh, isolated scenario,
  * how to tell if the dangerous outcome happened (``dangerous``),
  * which single defense layer is *primary* for stopping it.

Import :data:`ATTACKS` to iterate the whole ladder in order.
"""

from __future__ import annotations

from .base import Attack, run_attack
from . import (
    a01_direct_injection,
    a02_indirect_injection,
    a03_tool_result_poisoning,
    a04_confused_deputy,
    a05_data_exfiltration,
    a06_unicode_smuggling,
)

ATTACKS = [
    a01_direct_injection.ATTACK,
    a02_indirect_injection.ATTACK,
    a03_tool_result_poisoning.ATTACK,
    a04_confused_deputy.ATTACK,
    a05_data_exfiltration.ATTACK,
    a06_unicode_smuggling.ATTACK,
]

__all__ = ["Attack", "run_attack", "ATTACKS"]
