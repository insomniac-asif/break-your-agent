"""Run every attack undefended vs defended and print a graded table.

    $ python -m break_your_agent            # or: break-your-agent

Everything here runs on the deterministic mock model — no network, no GPU.
"""

from __future__ import annotations

import sys
from typing import List, Tuple

from .attacks import ATTACKS
from .attacks.base import HARDENED, UNDEFENDED


def _row(attack) -> Tuple[str, str, str, bool, bool]:
    undefended_pwned = attack.is_pwned(UNDEFENDED)
    hardened_pwned = attack.is_pwned(HARDENED)
    undef = "PWNED " if undefended_pwned else "safe  "
    deff = "PWNED " if hardened_pwned else "BLOCKED"
    return attack.id, undef, deff, undefended_pwned, hardened_pwned


def render() -> Tuple[str, bool]:
    lines: List[str] = []
    lines.append("break-your-agent — scorecard (deterministic mock model)")
    lines.append("=" * 78)
    header = f"{'ID':<4} {'ATTACK':<34} {'UNDEFENDED':<11} {'DEFENDED':<9}"
    lines.append(header)
    lines.append("-" * 78)

    exploited_undefended = 0
    blocked_defended = 0
    all_correct = True

    for attack in ATTACKS:
        aid, undef, deff, u_pwned, d_pwned = _row(attack)
        if u_pwned:
            exploited_undefended += 1
        if not d_pwned:
            blocked_defended += 1
        # The lab's own invariant: every attack must pop undefended and be
        # blocked when hardened. Flag any regression loudly.
        if not (u_pwned and not d_pwned):
            all_correct = False
        title = attack.title[:33]
        lines.append(f"{aid:<4} {title:<34} {undef:<11} {deff:<9}")

    lines.append("-" * 78)
    lines.append(
        f"undefended: {exploited_undefended}/{len(ATTACKS)} attacks succeeded   |   "
        f"defended: {blocked_defended}/{len(ATTACKS)} attacks blocked"
    )
    lines.append("")
    lines.append("Primary defense per attack:")
    for attack in ATTACKS:
        lines.append(f"  {attack.id}  {attack.title:<34} -> {attack.primary_defense}")
    lines.append("")
    lines.append(
        "Note: these are illustrative, fully-sandboxed toy attacks on a scripted "
        "mock model,\nnot a scanner or a benchmark. See the README threat model."
    )
    return "\n".join(lines), all_correct


def main() -> int:
    text, ok = render()
    print(text)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
