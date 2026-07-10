"""The core invariant of the lab, checked for every attack on the mock model:

    * undefended  -> the dangerous outcome HAPPENS  (PWNED)
    * hardened    -> the dangerous outcome DOES NOT  (BLOCKED)
    * the single "primary" defense layer is enough to block it

All offline, deterministic, no GPU.
"""

from __future__ import annotations

import pytest

from break_your_agent.attacks import ATTACKS
from break_your_agent.attacks.base import HARDENED, UNDEFENDED

IDS = [a.id for a in ATTACKS]


@pytest.mark.parametrize("attack", ATTACKS, ids=IDS)
def test_undefended_is_pwned(attack):
    assert attack.is_pwned(UNDEFENDED), f"{attack.id} should succeed undefended"


@pytest.mark.parametrize("attack", ATTACKS, ids=IDS)
def test_hardened_blocks(attack):
    assert not attack.is_pwned(HARDENED), f"{attack.id} should be blocked when hardened"


@pytest.mark.parametrize("attack", ATTACKS, ids=IDS)
def test_primary_defense_alone_blocks(attack):
    assert not attack.is_pwned(
        attack.minimal_policy
    ), f"{attack.id} primary defense ({attack.primary_defense}) should block it"


def test_ladder_is_complete():
    assert len(ATTACKS) == 11
    assert IDS == ["A01", "A02", "A03", "A04", "A05", "A06",
                   "A07", "A08", "A09", "A10", "A11"]
    assert len(set(IDS)) == len(IDS)  # ids are unique
