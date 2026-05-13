"""Tests for the interceptor."""
import pytest
from unittest.mock import MagicMock

from lexecon.enforcement.interceptor import Interceptor
from lexecon.enforcement.policy_engine import PolicyEngine
from lexecon.enforcement.decision import Decision, DecisionType
from lexecon.audit.ledger import Ledger
from lexecon.audit.signer import Signer


@pytest.fixture
def temp_ledger(tmp_path):
    """Create a ledger in a temp directory."""
    signer = Signer(key_dir=tmp_path / "keys")
    ledger = Ledger(ledger_path=tmp_path / "ledger.jsonl", signer=signer)
    return ledger


def test_interceptor_never_executes_blocked_tool(temp_ledger, monkeypatch):
    """
    MOST IMPORTANT TEST.
    When policy returns BLOCK, the tool must NEVER execute.
    """
    shell_run_called = False

    def fake_shell_run(executable, args, timeout=10):
        nonlocal shell_run_called
        shell_run_called = True
        return {"stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr("lexecon.tools.shell.shell_run", fake_shell_run)

    policy_engine = PolicyEngine()
    interceptor = Interceptor(policy_engine, temp_ledger)

    tool_call = {"tool": "shell.run", "args": {"executable": "rm", "args": ["-rf", "./important_data"]}}
    result = interceptor.intercept(tool_call)

    assert result["decision"] == "BLOCK"
    assert result["executed"] is False
    assert result["tool_result"] is None
    assert shell_run_called is False, "shell_run MUST NOT be called when BLOCKed"


def test_interceptor_executes_allowed_tool(temp_ledger, monkeypatch):
    """When policy returns ALLOW, the tool must execute and return result."""
    def fake_shell_run(executable, args, timeout=10):
        return {"stdout": "hello", "stderr": "", "returncode": 0}

    monkeypatch.setattr("lexecon.tools.shell.shell_run", fake_shell_run)

    policy_engine = PolicyEngine()
    interceptor = Interceptor(policy_engine, temp_ledger)

    tool_call = {"tool": "shell.run", "args": {"executable": "echo", "args": ["hello"]}}
    result = interceptor.intercept(tool_call)

    assert result["decision"] == "ALLOW"
    assert result["executed"] is True
    assert result["tool_result"] is not None
    assert result["tool_result"]["stdout"] == "hello"


def test_blocked_call_returns_correct_structure(temp_ledger, monkeypatch):
    """Blocked call must return structured output with all fields."""
    monkeypatch.setattr(
        "lexecon.tools.shell.shell_run",
        lambda exe, args, timeout=10: {"stdout": "", "stderr": "", "returncode": 0},
    )

    policy_engine = PolicyEngine()
    interceptor = Interceptor(policy_engine, temp_ledger)

    tool_call = {"tool": "shell.run", "args": {"executable": "rm", "args": ["-rf", "/"]}}
    result = interceptor.intercept(tool_call)

    assert "decision" in result
    assert "executed" in result
    assert "tool_result" in result
    assert "audit_record_id" in result
    assert "reason" in result
    assert result["decision"] == "BLOCK"
    assert result["executed"] is False
    assert isinstance(result["audit_record_id"], str)
    assert len(result["audit_record_id"]) > 0


def test_audit_record_written_for_blocked_call(temp_ledger, monkeypatch):
    """Every blocked call must produce an audit record."""
    monkeypatch.setattr(
        "lexecon.tools.shell.shell_run",
        lambda exe, args, timeout=10: {"stdout": "", "stderr": "", "returncode": 0},
    )

    policy_engine = PolicyEngine()
    interceptor = Interceptor(policy_engine, temp_ledger)

    tool_call = {"tool": "shell.run", "args": {"executable": "rm", "args": ["-rf", "/data"]}}
    result = interceptor.intercept(tool_call)

    records = temp_ledger.read_all_records()
    assert len(records) == 1
    assert records[0].record_id == result["audit_record_id"]
    assert records[0].decision == "BLOCK"


def test_audit_record_written_for_allowed_call(temp_ledger, monkeypatch):
    """Every allowed call must produce an audit record."""
    monkeypatch.setattr(
        "lexecon.tools.shell.shell_run",
        lambda exe, args, timeout=10: {"stdout": "out", "stderr": "", "returncode": 0},
    )

    policy_engine = PolicyEngine()
    interceptor = Interceptor(policy_engine, temp_ledger)

    tool_call = {"tool": "shell.run", "args": {"executable": "echo", "args": ["test"]}}
    result = interceptor.intercept(tool_call)

    records = temp_ledger.read_all_records()
    assert len(records) == 1
    assert records[0].decision == "ALLOW"


def test_interceptor_fail_closed_on_ledger_error(monkeypatch):
    """If ledger write fails, interceptor must fail closed (BLOCK)."""
    bad_ledger = MagicMock()
    bad_ledger.write_record.side_effect = RuntimeError("Ledger is full")

    policy_engine = PolicyEngine()
    interceptor = Interceptor(policy_engine, bad_ledger)

    tool_call = {"tool": "shell.run", "args": {"executable": "echo", "args": ["hello"]}}
    result = interceptor.intercept(tool_call)

    assert result["decision"] == "BLOCK"
    assert result["executed"] is False


def test_interceptor_never_executes_wrong_tool_name(temp_ledger, monkeypatch):
    """SECURITY: unsupported tool names must BLOCK and never execute."""
    shell_run_called = False

    def fake_shell_run(executable, args, timeout=10):
        nonlocal shell_run_called
        shell_run_called = True
        return {"stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr("lexecon.tools.shell.shell_run", fake_shell_run)

    policy_engine = PolicyEngine()
    interceptor = Interceptor(policy_engine, temp_ledger)

    tool_call = {"tool": "file.read", "args": {"executable": "rm", "args": ["-rf", "/"]}}
    result = interceptor.intercept(tool_call)

    assert result["decision"] == "BLOCK"
    assert result["executed"] is False
    assert shell_run_called is False, "shell_run must NOT execute for wrong tool name"
    assert result["tool_result"] is None


def test_interceptor_defense_in_depth_blocks_allowed_unsupported_tool(temp_ledger, monkeypatch):
    """Even if a bad policy engine ALLOWs an unsupported tool, interceptor must not execute it."""
    from lexecon.enforcement.decision import Decision, DecisionType

    class BadPolicyEngine:
        def evaluate(self, tool_call):
            return Decision(DecisionType.ALLOW, "bad allow", "bad_policy")

    shell_run_called = False

    def fake_shell_run(executable, args, timeout=10):
        nonlocal shell_run_called
        shell_run_called = True
        return {"stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr("lexecon.tools.shell.shell_run", fake_shell_run)
    interceptor = Interceptor(BadPolicyEngine(), temp_ledger)

    result = interceptor.intercept({"tool": "file.read", "args": {"executable": "rm", "args": ["-rf", "/"]}})

    assert result["decision"] == "BLOCK"
    assert result["executed"] is False
    assert shell_run_called is False


def test_audit_record_id_preserved_when_execution_raises(temp_ledger, monkeypatch):
    """audit_record_id must be non-empty even when shell_run raises after ALLOW."""
    def exploding_shell_run(executable, args, timeout=10):
        raise RuntimeError("subprocess failed unexpectedly")

    monkeypatch.setattr("lexecon.tools.shell.shell_run", exploding_shell_run)

    policy_engine = PolicyEngine()
    interceptor = Interceptor(policy_engine, temp_ledger)

    tool_call = {"tool": "shell.run", "args": {"executable": "echo", "args": ["hello"]}}
    result = interceptor.intercept(tool_call)

    assert result["decision"] == "BLOCK"
    assert result["executed"] is False
    assert result["audit_record_id"] != "", "audit_record_id must be preserved even when execution raises"

    # Confirm the audit record is actually in the ledger
    records = temp_ledger.read_all_records()
    assert len(records) == 1
    assert records[0].record_id == result["audit_record_id"]
