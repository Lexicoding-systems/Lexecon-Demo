"""
Characterization tests for malformed tool_call payloads.

Every case must fail closed: decision == BLOCK, executed == False,
shell_run never called, no uncaught exception escapes.

These tests target both PolicyEngine.evaluate() and Interceptor.intercept()
because the interceptor is the real trust boundary and must not rely solely
on the policy engine for defence.
"""
import pytest
from lexecon.enforcement.policy_engine import PolicyEngine
from lexecon.enforcement.interceptor import Interceptor
from lexecon.enforcement.decision import DecisionType
from lexecon.audit.ledger import Ledger
from lexecon.audit.signer import Signer


@pytest.fixture
def engine():
    return PolicyEngine()


@pytest.fixture
def temp_ledger(tmp_path):
    signer = Signer(key_dir=tmp_path / "keys")
    return Ledger(ledger_path=tmp_path / "ledger.jsonl", signer=signer)


@pytest.fixture
def interceptor(temp_ledger):
    return Interceptor(PolicyEngine(), temp_ledger)


def _no_exec(monkeypatch):
    """Patch shell_run to fail loudly if called."""
    called = []

    def boom(executable, args, timeout=10):
        called.append(True)
        raise AssertionError("shell_run must not be called for malformed payload")

    monkeypatch.setattr("lexecon.tools.shell.shell_run", boom)
    return called


# ---------------------------------------------------------------------------
# PolicyEngine — top-level non-dict shapes
# ---------------------------------------------------------------------------

class TestPolicyEngineTopLevelNonDict:
    def test_string_input(self, engine):
        r = engine.evaluate("not a dict")
        assert r.decision == DecisionType.BLOCK
        assert r.policy_id == "error"

    def test_list_input(self, engine):
        r = engine.evaluate([{"tool": "shell.run", "args": {"executable": "ls", "args": []}}])
        assert r.decision == DecisionType.BLOCK
        assert r.policy_id == "error"

    def test_int_input(self, engine):
        r = engine.evaluate(42)
        assert r.decision == DecisionType.BLOCK
        assert r.policy_id == "error"

    def test_bool_input(self, engine):
        r = engine.evaluate(True)
        assert r.decision == DecisionType.BLOCK
        assert r.policy_id == "error"


# ---------------------------------------------------------------------------
# PolicyEngine — args variations
# ---------------------------------------------------------------------------

class TestPolicyEngineArgsVariants:
    def test_args_none(self, engine):
        r = engine.evaluate({"tool": "shell.run", "args": None})
        assert r.decision == DecisionType.BLOCK
        assert r.policy_id == "error"

    def test_args_list(self, engine):
        r = engine.evaluate({"tool": "shell.run", "args": ["ls", "-la"]})
        assert r.decision == DecisionType.BLOCK
        assert r.policy_id == "error"

    def test_args_int(self, engine):
        r = engine.evaluate({"tool": "shell.run", "args": 99})
        assert r.decision == DecisionType.BLOCK
        assert r.policy_id == "error"


# ---------------------------------------------------------------------------
# PolicyEngine — executable variations
# ---------------------------------------------------------------------------

class TestPolicyEngineExecutableVariants:
    def test_executable_none(self, engine):
        r = engine.evaluate({"tool": "shell.run", "args": {"executable": None, "args": []}})
        assert r.decision == DecisionType.BLOCK
        assert r.policy_id == "error"

    def test_executable_int(self, engine):
        r = engine.evaluate({"tool": "shell.run", "args": {"executable": 42, "args": []}})
        assert r.decision == DecisionType.BLOCK
        assert r.policy_id == "error"

    def test_executable_empty_string(self, engine):
        r = engine.evaluate({"tool": "shell.run", "args": {"executable": "", "args": []}})
        assert r.decision == DecisionType.BLOCK
        assert r.policy_id == "error"

    def test_executable_whitespace(self, engine):
        r = engine.evaluate({"tool": "shell.run", "args": {"executable": "   ", "args": []}})
        assert r.decision == DecisionType.BLOCK
        assert r.policy_id == "error"

    def test_executable_bool(self, engine):
        r = engine.evaluate({"tool": "shell.run", "args": {"executable": False, "args": []}})
        assert r.decision == DecisionType.BLOCK
        assert r.policy_id == "error"


# ---------------------------------------------------------------------------
# PolicyEngine — args-list element variants
# ---------------------------------------------------------------------------

class TestPolicyEngineArgListElementVariants:
    def test_arg_element_none(self, engine):
        r = engine.evaluate({"tool": "shell.run", "args": {"executable": "ls", "args": [None]}})
        assert r.decision == DecisionType.BLOCK
        assert r.policy_id == "error"

    def test_arg_element_int(self, engine):
        r = engine.evaluate({"tool": "shell.run", "args": {"executable": "ls", "args": [1, 2]}})
        assert r.decision == DecisionType.BLOCK
        assert r.policy_id == "error"

    def test_arg_element_mixed(self, engine):
        r = engine.evaluate({"tool": "shell.run", "args": {"executable": "ls", "args": ["-la", 99]}})
        assert r.decision == DecisionType.BLOCK
        assert r.policy_id == "error"


# ---------------------------------------------------------------------------
# Interceptor — fail-closed: no execution, structured result, no exception
# ---------------------------------------------------------------------------

class TestInterceptorFailClosed:

    def _assert_blocked(self, result):
        assert result["decision"] == "BLOCK"
        assert result["executed"] is False
        assert result["tool_result"] is None

    def test_non_dict_string(self, interceptor, monkeypatch):
        called = _no_exec(monkeypatch)
        result = interceptor.intercept("not a dict")
        self._assert_blocked(result)
        assert called == [], "shell_run must not be called"

    def test_non_dict_list(self, interceptor, monkeypatch):
        called = _no_exec(monkeypatch)
        result = interceptor.intercept([{"tool": "shell.run"}])
        self._assert_blocked(result)
        assert called == []

    def test_non_dict_none(self, interceptor, monkeypatch):
        called = _no_exec(monkeypatch)
        result = interceptor.intercept(None)
        self._assert_blocked(result)
        assert called == []

    def test_args_none(self, interceptor, monkeypatch):
        called = _no_exec(monkeypatch)
        result = interceptor.intercept({"tool": "shell.run", "args": None})
        self._assert_blocked(result)
        assert called == []

    def test_args_string(self, interceptor, monkeypatch):
        called = _no_exec(monkeypatch)
        result = interceptor.intercept({"tool": "shell.run", "args": "ls -la"})
        self._assert_blocked(result)
        assert called == []

    def test_executable_none(self, interceptor, monkeypatch):
        called = _no_exec(monkeypatch)
        result = interceptor.intercept({"tool": "shell.run", "args": {"executable": None, "args": []}})
        self._assert_blocked(result)
        assert called == []

    def test_executable_int(self, interceptor, monkeypatch):
        called = _no_exec(monkeypatch)
        result = interceptor.intercept({"tool": "shell.run", "args": {"executable": 42, "args": []}})
        self._assert_blocked(result)
        assert called == []

    def test_executable_empty_string(self, interceptor, monkeypatch):
        called = _no_exec(monkeypatch)
        result = interceptor.intercept({"tool": "shell.run", "args": {"executable": "", "args": []}})
        self._assert_blocked(result)
        assert called == []

    def test_executable_whitespace(self, interceptor, monkeypatch):
        called = _no_exec(monkeypatch)
        result = interceptor.intercept({"tool": "shell.run", "args": {"executable": "   ", "args": []}})
        self._assert_blocked(result)
        assert called == []

    def test_args_list_with_non_string(self, interceptor, monkeypatch):
        called = _no_exec(monkeypatch)
        result = interceptor.intercept({"tool": "shell.run", "args": {"executable": "ls", "args": [1, 2]}})
        self._assert_blocked(result)
        assert called == []

    def test_unsupported_tool(self, interceptor, monkeypatch):
        called = _no_exec(monkeypatch)
        result = interceptor.intercept({"tool": "file.delete", "args": {"path": "/etc/passwd"}})
        self._assert_blocked(result)
        assert called == []

    def test_missing_tool_key(self, interceptor, monkeypatch):
        called = _no_exec(monkeypatch)
        result = interceptor.intercept({"args": {"executable": "ls", "args": []}})
        self._assert_blocked(result)
        assert called == []

    def test_tool_is_none(self, interceptor, monkeypatch):
        called = _no_exec(monkeypatch)
        result = interceptor.intercept({"tool": None, "args": {"executable": "ls", "args": []}})
        self._assert_blocked(result)
        assert called == []

    def test_tool_is_int(self, interceptor, monkeypatch):
        called = _no_exec(monkeypatch)
        result = interceptor.intercept({"tool": 123, "args": {"executable": "ls", "args": []}})
        self._assert_blocked(result)
        assert called == []
