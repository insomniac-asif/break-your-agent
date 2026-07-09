"""Prove that the *right* defense is necessary — not just that hardening works.

These tests are the teaching payload: they show a plausible-but-insufficient
defense still getting popped, so you understand which layer is actually
load-bearing for each attack class.
"""

from __future__ import annotations

from break_your_agent.attacks import (
    a01_direct_injection,
    a02_indirect_injection,
    a05_data_exfiltration,
    a06_unicode_smuggling,
)
from break_your_agent.policy import DefensePolicy


def test_trust_tiering_does_not_stop_direct_injection():
    # A01 lives in the trusted user channel; sanitizing untrusted content can't help.
    weak = DefensePolicy(trust_tiering=True, arg_dlp=True, acl=True)  # no gate_privileged
    assert a01_direct_injection.ATTACK.is_pwned(weak)


def test_approval_sentinel_does_not_stop_indirect_injection():
    # A02's sink (fetch_url) is not a privileged tool, so gating mutating tools
    # is no help — you need trust-tiering.
    weak = DefensePolicy(gate_privileged=True, arg_dlp=True, acl=True)  # no trust_tiering
    assert a02_indirect_injection.ATTACK.is_pwned(weak)


def test_everything_but_dlp_still_leaks_the_secret():
    # A05 hides the secret in a fetch_url argument. Only egress DLP catches it.
    weak = DefensePolicy(
        gate_privileged=True, acl=True, trust_tiering=True, normalize_first=True
    )  # no arg_dlp
    assert a05_data_exfiltration.ATTACK.is_pwned(weak)


def test_ascii_only_filter_misses_fullwidth_smuggling():
    # A06: stripping directives WITHOUT normalizing first fails on fullwidth.
    weak = DefensePolicy(trust_tiering=True, normalize_first=False)
    assert a06_unicode_smuggling.ATTACK.is_pwned(weak)

    strong = DefensePolicy(trust_tiering=True, normalize_first=True)
    assert not a06_unicode_smuggling.ATTACK.is_pwned(strong)
