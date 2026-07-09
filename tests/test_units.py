"""Unit tests for the primitives: text grammar, tools, agent loop, scorecard."""

from __future__ import annotations

from break_your_agent import Agent, DefensePolicy, Environment, MockModel, NullPolicy
from break_your_agent._text import (
    normalize_fullwidth,
    parse_directives,
    strip_directives,
)
from break_your_agent.scorecard import render


def test_normalize_fullwidth_maps_to_ascii():
    assert normalize_fullwidth("ＦＥＴＣＨ：") == "FETCH:"
    assert normalize_fullwidth("｜＜＞") == "|<>"
    assert normalize_fullwidth("a　b") == "a b"


def test_parse_directives_reads_all_forms():
    text = "RUN: ls\nFETCH: http://x\nREADNOTE: n\nSEND: a | hi"
    found = parse_directives(text)
    names = [n for n, _ in found]
    assert names == ["run_cmd", "fetch_url", "read_note", "send_message"]
    assert found[3][1] == {"to": "a", "body": "hi"}


def test_strip_directives_neutralizes_only_with_normalization():
    line = "ＲＵＮ： rm -rf /"
    assert "rm -rf" in strip_directives(line, normalize_first=False)
    assert "rm -rf" not in strip_directives(line, normalize_first=True)


def test_sandboxed_run_cmd_never_executes():
    env = Environment()
    out = env.run_cmd("cat /etc/passwd", _ctx={})
    assert out.startswith("[sandbox echo]")
    assert env.commands == ["cat /etc/passwd"]


def test_agent_runs_benign_task():
    env = Environment(notes={"welcome": "hi"})
    agent = Agent(model=MockModel(), env=env, policy=NullPolicy())
    result = agent.run("READNOTE: welcome", {"user_id": "u"})
    assert result.executed("read_note")
    assert result.final.startswith("done")


def test_agent_records_block_reason():
    env = Environment(notes={"x": "y"})
    policy = DefensePolicy(gate_privileged=True)
    agent = Agent(model=MockModel(), env=env, policy=policy)
    result = agent.run("RUN: whoami", {"user_id": "u", "owner_approved": False})
    assert not result.executed("run_cmd")
    assert "NEEDS_OWNER_APPROVAL" in (result.blocked_reason("run_cmd") or "")


def test_approved_owner_may_run_privileged_tool():
    env = Environment()
    policy = DefensePolicy(gate_privileged=True)
    agent = Agent(model=MockModel(), env=env, policy=policy)
    result = agent.run("RUN: echo hi", {"user_id": "owner-1", "owner_approved": True})
    assert result.executed("run_cmd")


def test_scorecard_render_is_all_correct():
    text, ok = render()
    assert ok is True
    assert "PWNED" in text and "BLOCKED" in text
    for aid in ("A01", "A02", "A03", "A04", "A05", "A06"):
        assert aid in text
