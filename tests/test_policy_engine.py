"""Tests for the policy engine."""
import pytest
from lexecon.enforcement.policy_engine import PolicyEngine
from lexecon.enforcement.decision import DecisionType


def test_policy_blocks_rm_rf():
    """Policy engine must BLOCK rm -rf command."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": {"command": "rm -rf /important"}})
    assert result.decision == DecisionType.BLOCK
    assert result.policy_id == "block_destructive_shell"


def test_policy_blocks_sudo_rm():
    """Policy engine must BLOCK sudo rm command."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": {"command": "sudo rm -rf /etc"}})
    assert result.decision == DecisionType.BLOCK


def test_policy_blocks_mkfs():
    """Policy engine must BLOCK mkfs command."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": {"command": "mkfs.ext4 /dev/sda1"}})
    assert result.decision == DecisionType.BLOCK


def test_policy_blocks_diskutil_erase():
    """Policy engine must BLOCK diskutil erase command."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": {"command": "diskutil eraseDisk JHFS+ NewDisk /dev/disk1"}})
    assert result.decision == DecisionType.BLOCK


def test_policy_allows_safe_command():
    """Policy engine must ALLOW safe commands like ls."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": {"command": "ls -la"}})
    assert result.decision == DecisionType.ALLOW


def test_policy_allows_echo():
    """Policy engine must ALLOW echo command."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": {"command": "echo hello world"}})
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
    # evaluate(None) would crash in .get() on None — this tests fail-closed
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


def test_policy_non_string_command():
    """Tool call with non-string command should BLOCK (fail-closed: malformed)."""
    engine = PolicyEngine()
    result = engine.evaluate({"tool": "shell.run", "args": {"command": ["rm", "-rf", "/"]}})
    assert result.decision == DecisionType.BLOCK
    assert result.policy_id == "error"
