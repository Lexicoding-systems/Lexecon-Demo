"""Tests for the Anthropic tool_use adapter."""
import pytest
from lexecon.adapters.anthropic_adapter import from_anthropic_tool_use


def test_adapter_bash_tool_basic():
    block = {"type": "tool_use", "id": "t1", "name": "bash", "input": {"command": "ls -la"}}
    tc = from_anthropic_tool_use(block)
    assert tc["tool"] == "shell.run"
    assert tc["args"]["executable"] == "ls"
    assert tc["args"]["args"] == ["-la"]


def test_adapter_bash_destructive_command():
    block = {"type": "tool_use", "name": "bash", "input": {"command": "rm -rf ./data"}}
    tc = from_anthropic_tool_use(block)
    assert tc["tool"] == "shell.run"
    assert tc["args"]["executable"] == "rm"
    assert tc["args"]["args"] == ["-rf", "./data"]


def test_adapter_shell_tool_name():
    block = {"type": "tool_use", "name": "shell", "input": {"command": "echo hello world"}}
    tc = from_anthropic_tool_use(block)
    assert tc["tool"] == "shell.run"
    assert tc["args"]["executable"] == "echo"
    assert tc["args"]["args"] == ["hello", "world"]


def test_adapter_run_command_tool_name():
    block = {"type": "tool_use", "name": "run_command", "input": {"command": "pwd"}}
    tc = from_anthropic_tool_use(block)
    assert tc["tool"] == "shell.run"
    assert tc["args"]["executable"] == "pwd"
    assert tc["args"]["args"] == []


def test_adapter_execute_tool_name():
    block = {"type": "tool_use", "name": "execute", "input": {"command": "date -u"}}
    tc = from_anthropic_tool_use(block)
    assert tc["tool"] == "shell.run"
    assert tc["args"]["executable"] == "date"
    assert tc["args"]["args"] == ["-u"]


def test_adapter_non_shell_tool_passthrough():
    block = {"type": "tool_use", "name": "read_file", "input": {"path": "/etc/hosts"}}
    tc = from_anthropic_tool_use(block)
    assert tc["tool"] == "read_file"
    assert tc["args"] == {"path": "/etc/hosts"}


def test_adapter_empty_command():
    block = {"type": "tool_use", "name": "bash", "input": {"command": ""}}
    tc = from_anthropic_tool_use(block)
    assert tc["tool"] == "shell.run"
    assert tc["args"]["executable"] == ""
    assert tc["args"]["args"] == []


def test_adapter_quoted_args():
    block = {"type": "tool_use", "name": "bash", "input": {"command": 'echo "hello world"'}}
    tc = from_anthropic_tool_use(block)
    assert tc["tool"] == "shell.run"
    assert tc["args"]["executable"] == "echo"
    assert tc["args"]["args"] == ["hello world"]


def test_adapter_non_dict_raises():
    with pytest.raises(ValueError):
        from_anthropic_tool_use("not a dict")


def test_adapter_null_command_fails_closed():
    """input: {"command": null} must not raise — returns empty executable."""
    block = {"type": "tool_use", "name": "bash", "input": {"command": None}}
    tc = from_anthropic_tool_use(block)
    assert tc["tool"] == "shell.run"
    assert tc["args"]["executable"] == ""
    assert tc["args"]["args"] == []


def test_adapter_non_string_command_fails_closed():
    """input: {"command": 42} must not raise — returns empty executable."""
    block = {"type": "tool_use", "name": "bash", "input": {"command": 42}}
    tc = from_anthropic_tool_use(block)
    assert tc["tool"] == "shell.run"
    assert tc["args"]["executable"] == ""
    assert tc["args"]["args"] == []


def test_adapter_null_input_fails_closed():
    """input: null must not raise — treated as empty input."""
    block = {"type": "tool_use", "name": "bash", "input": None}
    tc = from_anthropic_tool_use(block)
    assert tc["tool"] == "shell.run"
    assert tc["args"]["executable"] == ""
