"""Tests for the policy engine."""
import pytest
from lexecon.enforcement.policy_engine import PolicyEngine
from lexecon.enforcement.decision import DecisionType


def test_policy_blocks_rm_rf():
    """Pattern check must BLOCK even allowlisted executables passing dangerous args."""
    engine = PolicyEngine()
    # echo is allowlisted but the arg string contains "rm -rf" — still blocked.
    result = engine.evaluate({"tool": "shell.run", "args": {"executable": "echo", "args": ["rm", "-rf", "/important"]}})
    assert result.decision == DecisionType.BLOCK
    assert result.policy_id == "block_destructive_shell"


def test_policy_blocks_sudo_rm():
    """Pattern check must BLOCK when arg string contains 'sudo rm'."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": {"executable": "echo", "args": ["sudo", "rm", "-rf", "/etc"]}})
    assert result.decision == DecisionType.BLOCK


def test_policy_blocks_mkfs():
    """Pattern check must BLOCK when arg string contains 'mkfs'."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": {"executable": "echo", "args": ["mkfs.ext4", "/dev/sda1"]}})
    assert result.decision == DecisionType.BLOCK


def test_policy_blocks_diskutil_erase():
    """Pattern check must BLOCK when arg string contains 'diskutil erase'."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": {"executable": "echo", "args": ["diskutil", "erase", "JHFS+", "NewDisk", "/dev/disk1"]}})
    assert result.decision == DecisionType.BLOCK


def test_policy_blocks_non_allowlisted_executable():
    """Executable not in allowlist must be BLOCK regardless of args."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": {"executable": "rm", "args": ["-la"]}})
    assert result.decision == DecisionType.BLOCK
    assert result.policy_id == "not_allowlisted"


def test_policy_allows_safe_command():
    """Policy engine must ALLOW allowlisted commands with benign args."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": {"executable": "ls", "args": ["-la"]}})
    assert result.decision == DecisionType.ALLOW


def test_policy_allows_echo():
    """Policy engine must ALLOW echo with benign args."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": {"executable": "echo", "args": ["hello", "world"]}})
    assert result.decision == DecisionType.ALLOW


def test_policy_blocks_different_tool():
    """Unsupported tools are blocked in the MVP, not silently allowed."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "file.read", "args": {"path": "/etc/passwd"}})
    assert result.decision == DecisionType.BLOCK
    assert result.policy_id == "unsupported_tool"


def test_policy_fail_closed_on_none():
    """Policy engine should not crash on None input."""
    engine = PolicyEngine()
    result = engine.evaluate(None)
    assert result.decision == DecisionType.BLOCK
    assert result.policy_id == "error"


def test_policy_no_args():
    """shell.run without args is malformed and must BLOCK."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run"})
    assert result.decision == DecisionType.BLOCK
    assert result.policy_id == "error"


def test_policy_non_dict_args():
    """Tool call with non-dict args should BLOCK (fail-closed: malformed)."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": "not a dict"})
    assert result.decision == DecisionType.BLOCK
    assert result.policy_id == "error"


def test_policy_non_string_executable():
    """Tool call with non-string executable should BLOCK (fail-closed: malformed)."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": {"executable": ["rm", "-rf", "/"]}})
    assert result.decision == DecisionType.BLOCK
    assert result.policy_id == "error"


def test_policy_non_list_args():
    """Tool call with non-list args field should BLOCK (fail-closed: malformed)."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": {"executable": "ls", "args": "-la"}})
    assert result.decision == DecisionType.BLOCK
    assert result.policy_id == "error"


def test_policy_non_string_arg_elements():
    """Args list containing non-string elements must BLOCK before ALLOW or dispatch."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": {"executable": "ls", "args": [1]}})
    assert result.decision == DecisionType.BLOCK
    assert result.policy_id == "error"
