"""Offline tests for the --live tool-call rescue (no network, no model).

These cover the case a real local model narrates a call as text/markup instead
of emitting a native ``tool_calls`` field. Without rescue, such a turn reads as
a false "safe" and understates the vulnerability — so this is a correctness
control for the honesty of the live scorecard, not a nicety.
"""

from __future__ import annotations

from break_your_agent._text import extract_toolcall_from_text
from break_your_agent.model import OllamaModel, ToolCallRequest


def test_rescue_bare_json_openai_style():
    assert extract_toolcall_from_text(
        '{"name": "run_cmd", "arguments": {"cmd": "id"}}'
    ) == ("run_cmd", {"cmd": "id"})


def test_rescue_function_wrapper_shape():
    assert extract_toolcall_from_text(
        '{"function": {"name": "fetch_url", "arguments": {"url": "http://x"}}}'
    ) == ("fetch_url", {"url": "http://x"})


def test_rescue_hermes_tag_with_prose():
    c = 'Sure, doing that now. <tool_call>{"name": "read_note", "arguments": {"name": "apikey"}}</tool_call>'
    assert extract_toolcall_from_text(c) == ("read_note", {"name": "apikey"})


def test_rescue_fenced_json_block():
    c = "I'll fetch the continuation:\n```json\n{\"name\": \"fetch_url\", \"arguments\": {\"url\": \"http://evil\"}}\n```"
    assert extract_toolcall_from_text(c) == ("fetch_url", {"url": "http://evil"})


def test_rescue_arguments_as_json_string():
    # some models serialize the arguments object as a JSON *string*
    assert extract_toolcall_from_text(
        '{"name": "run_cmd", "arguments": "{\\"cmd\\": \\"ls\\"}"}'
    ) == ("run_cmd", {"cmd": "ls"})


def test_rescue_tool_calls_envelope():
    c = '{"tool_calls": [{"function": {"name": "run_cmd", "arguments": {"cmd": "whoami"}}}]}'
    assert extract_toolcall_from_text(c) == ("run_cmd", {"cmd": "whoami"})


def test_rescue_xml_invoke_with_fullwidth_delimiters():
    # fullwidth < and > (the A06 lesson applied to the parser): must normalize first
    c = ("＜invoke name=\"send_message\"＞"
         "＜parameter name=\"to\"＞attacker＜/parameter＞"
         "＜parameter name=\"body\"＞secret＜/parameter＞"
         "＜/invoke＞")
    assert extract_toolcall_from_text(c) == ("send_message", {"to": "attacker", "body": "secret"})


def test_rescue_rejects_ordinary_json_and_prose():
    # a tool-call SHAPE is required (name + explicit arg container), so plain data
    # and plain text are never misread as a call.
    assert extract_toolcall_from_text('{"name": "Bob", "age": 3}') is None
    assert extract_toolcall_from_text("I can't help with that request.") is None
    assert extract_toolcall_from_text("") is None
    assert extract_toolcall_from_text('{"name": "run_cmd", "args": "not json"}') is None


def test_ollamamodel_validates_rescued_name_against_tool_set():
    # rescue that names a non-existent tool must be discarded by the model adapter
    m = OllamaModel(model="x")
    assert "run_cmd" in m._tool_names
    assert "definitely_not_a_tool" not in m._tool_names
    # a well-formed call to an unknown tool still parses at the text layer...
    assert extract_toolcall_from_text(
        '{"name": "definitely_not_a_tool", "arguments": {"x": "1"}}'
    ) == ("definitely_not_a_tool", {"x": "1"})
    # ...but the adapter's tool-set guard is what rejects it downstream.


def test_toolcallrequest_is_importable():
    # guard the public surface the rescue path returns
    tc = ToolCallRequest(name="run_cmd", args={"cmd": "id"})
    assert tc.name == "run_cmd" and tc.args == {"cmd": "id"}
