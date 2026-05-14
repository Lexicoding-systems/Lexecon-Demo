"""Tests for split-flag normalization in the policy engine."""
from pathlib import Path
import pytest
from lexecon.enforcement.policy_engine import PolicyEngine, _normalize_arg_string
from lexecon.enforcement.decision import DecisionType

DEMO_POLICY = Path(__file__).parent.parent / "lexecon" / "policies" / "demo_policy.yaml"


# ── _normalize_arg_string unit tests ─────────────────────────────────────────

def test_normalize_merges_split_short_flags():
    assert _normalize_arg_string("rm", ["-r", "-f", "."]) == "rm -rf ."


def test_normalize_leaves_combined_flags_unchanged():
    assert _normalize_arg_string("rm", ["-rf", "."]) == "rm -rf ."


def test_normalize_preserves_long_flags():
    assert _normalize_arg_string("ls", ["--all", "--human-readable"]) == "ls --all --human-readable"


def test_normalize_mixed_short_and_long():
    result = _normalize_arg_string("tar", ["-x", "-z", "--file", "a.tar.gz"])
    assert result == "tar -xz --file a.tar.gz"


def test_normalize_no_flags():
    assert _normalize_arg_string("echo", ["hello", "world"]) == "echo hello world"


def test_normalize_flags_then_positional():
    result = _normalize_arg_string("rm", ["-r", "-f", "/tmp/test"])
    assert result == "rm -rf /tmp/test"


# ── Policy engine: split-flag bypass is blocked ───────────────────────────────

def test_split_rf_flags_blocked_by_demo_policy():
    """rm -r -f must be caught the same as rm -rf (demo policy, rm is allowlisted)."""
    engine = PolicyEngine(policy_path=DEMO_POLICY)
    result = engine.evaluate({
        "tool": "shell.run",
        "args": {"executable": "rm", "args": ["-r", "-f", "./data"]},
    })
    assert result.decision == DecisionType.BLOCK
    assert result.policy_id == "block_destructive_shell"


def test_split_rf_flags_blocked_individually():
    """rm with -r and -f as separate args must be caught."""
    engine = PolicyEngine(policy_path=DEMO_POLICY)
    result = engine.evaluate({
        "tool": "shell.run",
        "args": {"executable": "rm", "args": ["-r", "-f"]},
    })
    assert result.decision == DecisionType.BLOCK
    assert result.policy_id == "block_destructive_shell"


def test_combined_rf_flags_still_blocked():
    """rm -rf must still be caught after normalization (no regression)."""
    engine = PolicyEngine(policy_path=DEMO_POLICY)
    result = engine.evaluate({
        "tool": "shell.run",
        "args": {"executable": "rm", "args": ["-rf", "./data"]},
    })
    assert result.decision == DecisionType.BLOCK
    assert result.policy_id == "block_destructive_shell"


def test_demo_policy_fires_correct_rule_id():
    """demo policy must produce policy_id block_destructive_shell, not not_allowlisted."""
    engine = PolicyEngine(policy_path=DEMO_POLICY)
    result = engine.evaluate({
        "tool": "shell.run",
        "args": {"executable": "rm", "args": ["-rf", "./important_data"]},
    })
    assert result.decision == DecisionType.BLOCK
    assert result.policy_id == "block_destructive_shell", (
        f"Demo must fire the pattern rule, not the allowlist check. Got: {result.policy_id!r}"
    )


def test_demo_policy_allows_safe_rm():
    """rm with benign args is allowed by demo policy (rm is on allowlist, no pattern match)."""
    engine = PolicyEngine(policy_path=DEMO_POLICY)
    result = engine.evaluate({
        "tool": "shell.run",
        "args": {"executable": "rm", "args": ["./old_log.txt"]},
    })
    assert result.decision == DecisionType.ALLOW


# ── Removed ESCALATE — verify it no longer exists ────────────────────────────

def test_escalate_removed_from_decision_type():
    """ESCALATE must not exist in DecisionType (it is a Phase 2 feature)."""
    from lexecon.enforcement.decision import DecisionType
    decision_names = {d.name for d in DecisionType}
    assert "ESCALATE" not in decision_names, (
        "ESCALATE is dead code until a handler is implemented. Remove it from DecisionType."
    )
