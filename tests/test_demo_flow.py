"""End-to-end demo flow test."""
import pytest
from unittest.mock import MagicMock

from lexecon.enforcement.interceptor import Interceptor
from lexecon.enforcement.policy_engine import PolicyEngine
from lexecon.audit.ledger import Ledger
from lexecon.audit.signer import Signer
from lexecon.audit.verifier import Verifier


def test_demo_flow_blocks_destructive_command(tmp_path, monkeypatch):
    """
    End-to-end: destructive command is blocked, does not execute,
    audit record is written, ledger verifies.
    """
    # Setup
    keys_dir = tmp_path / "keys"
    ledger_path = tmp_path / "ledger.jsonl"
    signer = Signer(key_dir=keys_dir)
    ledger = Ledger(ledger_path=ledger_path, signer=signer)
    policy_engine = PolicyEngine()
    interceptor = Interceptor(policy_engine, ledger)

    # Prevent actual shell execution
    shell_executed = False
    def fake_shell_run(executable, args, timeout=10):
        nonlocal shell_executed
        shell_executed = True
        return {"stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr("lexecon.tools.shell.shell_run", fake_shell_run)

    # Attempt destructive command (same as demo)
    tool_call = {
        "tool": "shell.run",
        "args": {"executable": "rm", "args": ["-rf", "./important_data"]},
    }
    result = interceptor.intercept(tool_call)

    # Assertions
    assert result["decision"] == "BLOCK", f"Expected BLOCK, got {result['decision']}"
    assert result["executed"] is False
    assert shell_executed is False, "Destructive command must NOT execute"
    assert result["audit_record_id"] != ""

    # Verify ledger
    verifier = Verifier(signer=signer)
    verification = verifier.verify_ledger(ledger_path)
    assert verification["valid"] is True, f"Ledger should be valid, errors: {verification['errors']}"
    assert verification["record_count"] == 1

    # Check audit record content
    records = ledger.read_all_records()
    assert len(records) == 1
    assert records[0].decision == "BLOCK"
    assert records[0].tool_name == "shell.run"
    assert records[0].signature != ""
    assert records[0].record_hash != ""
    assert records[0].previous_hash == "GENESIS"


def test_demo_flow_allows_safe_command(tmp_path, monkeypatch):
    """End-to-end: safe command is allowed and executes."""
    keys_dir = tmp_path / "keys"
    ledger_path = tmp_path / "ledger.jsonl"
    signer = Signer(key_dir=keys_dir)
    ledger = Ledger(ledger_path=ledger_path, signer=signer)
    policy_engine = PolicyEngine()
    interceptor = Interceptor(policy_engine, ledger)

    def fake_shell_run(executable, args, timeout=10):
        return {"stdout": "hello world", "stderr": "", "returncode": 0}

    monkeypatch.setattr("lexecon.tools.shell.shell_run", fake_shell_run)

    tool_call = {
        "tool": "shell.run",
        "args": {"executable": "echo", "args": ["hello", "world"]},
    }
    result = interceptor.intercept(tool_call)

    assert result["decision"] == "ALLOW"
    assert result["executed"] is True
    assert result["tool_result"]["stdout"] == "hello world"

    # Verify ledger
    verifier = Verifier(signer=signer)
    verification = verifier.verify_ledger(ledger_path)
    assert verification["valid"] is True
    assert verification["record_count"] == 1

    records = ledger.read_all_records()
    assert records[0].decision == "ALLOW"


def test_demo_flow_multiple_commands(tmp_path, monkeypatch):
    """Multiple commands produce a valid chain."""
    keys_dir = tmp_path / "keys"
    ledger_path = tmp_path / "ledger.jsonl"
    signer = Signer(key_dir=keys_dir)
    ledger = Ledger(ledger_path=ledger_path, signer=signer)
    policy_engine = PolicyEngine()
    interceptor = Interceptor(policy_engine, ledger)

    monkeypatch.setattr(
        "lexecon.tools.shell.shell_run",
        lambda exe, args, timeout=10: {"stdout": "", "stderr": "", "returncode": 0},
    )

    # Mix of blocked (rm not allowlisted) and allowed
    interceptor.intercept({"tool": "shell.run", "args": {"executable": "rm", "args": ["-rf", "/data"]}})
    interceptor.intercept({"tool": "shell.run", "args": {"executable": "ls", "args": ["-la"]}})
    interceptor.intercept({"tool": "shell.run", "args": {"executable": "echo", "args": ["test"]}})

    verifier = Verifier(signer=signer)
    verification = verifier.verify_ledger(ledger_path)
    assert verification["valid"] is True
    assert verification["record_count"] == 3

    records = ledger.read_all_records()
    assert records[0].decision == "BLOCK"
    assert records[1].decision == "ALLOW"
    assert records[2].decision == "ALLOW"
    assert records[0].previous_hash == "GENESIS"
    assert records[1].previous_hash == records[0].record_hash
    assert records[2].previous_hash == records[1].record_hash
