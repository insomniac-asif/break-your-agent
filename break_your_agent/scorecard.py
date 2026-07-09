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


def render_live(model_name: str, trials: int = 5, host: str = "http://localhost:11434") -> str:
    """Run every attack N times against a REAL local model (Ollama) and report the
    pwned RATE undefended vs defended.

    Real models are non-deterministic, so a rate (not a boolean) is the honest
    unit: it shows whether *this* model falls for each attack class and how
    reliably the defenses hold. Fully sandboxed — same toy tools as the mock.
    """
    from .model import OllamaModel

    def _model() -> OllamaModel:
        return OllamaModel(model=model_name, host=host)

    # Preflight: fail with a clear message instead of crashing mid-scorecard if
    # the model tag isn't reachable (wrong tag, ollama not running, etc.).
    try:
        _model()([{"role": "user", "content": "reply DONE"}], {})
    except Exception as exc:  # noqa: BLE001
        return (f"Could not reach model '{model_name}' at {host}:\n"
                f"  {type(exc).__name__}: {exc}\n"
                f"Is `ollama serve` running and the tag pulled?  (try: ollama pull {model_name})")

    def _pwned(attack, policy) -> object:
        # A real model (or ollama) can hiccup on any single call; a blip must not
        # abort the whole run. None = errored (counted separately, never as PWNED).
        try:
            return attack.is_pwned(policy, model=_model())
        except Exception:  # noqa: BLE001
            return None

    lines: List[str] = []
    lines.append(f"break-your-agent — LIVE scorecard   (model: {model_name}, {trials} trials/cell)")
    lines.append("=" * 78)
    lines.append(f"{'ID':<4} {'ATTACK':<34} {'UNDEFENDED':<12} {'DEFENDED':<10}")
    lines.append("-" * 78)

    total_cells = len(ATTACKS) * trials
    total_u = total_d = total_err = 0
    for attack in ATTACKS:
        u_res = [_pwned(attack, UNDEFENDED) for _ in range(trials)]
        d_res = [_pwned(attack, HARDENED) for _ in range(trials)]
        u = sum(1 for r in u_res if r is True)
        d = sum(1 for r in d_res if r is True)
        total_err += sum(1 for r in (u_res + d_res) if r is None)
        total_u += u
        total_d += d
        title = attack.title[:33]
        lines.append(f"{attack.id:<4} {title:<34} {f'{u}/{trials} PWNED':<12} {f'{d}/{trials} PWNED':<10}")

    lines.append("-" * 78)
    summary = (f"undefended: {total_u}/{total_cells} attack-runs succeeded   |   "
               f"defended: {total_cells - total_d}/{total_cells} blocked")
    if total_err:
        summary += f"   |   {total_err} model errors"
    lines.append(summary)
    lines.append("")
    lines.append("A real, non-deterministic local model on the same sandboxed tools. Rates vary")
    lines.append("run-to-run; this shows whether THIS model falls for each class, not a benchmark.")
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="break-your-agent",
        description="Run the attack/defense scorecard (mock by default; --live for a real model).",
    )
    p.add_argument(
        "--live", metavar="MODEL", default=None,
        help="Run against a real Ollama model (e.g. llama3.2:3b-instruct) instead of the mock.",
    )
    p.add_argument("--trials", type=int, default=5, help="Trials per cell for --live (default 5).")
    p.add_argument("--host", default="http://localhost:11434", help="Ollama host URL.")
    args = p.parse_args(argv)

    if args.live:
        print(render_live(args.live, trials=args.trials, host=args.host))
        return 0

    text, ok = render()
    print(text)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
