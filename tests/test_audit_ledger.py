"""Tests for audit ledger."""
import pytest
import json

from lexecon.audit.ledger import Ledger
from lexecon.audit.signer import Signer
from lexecon.audit.record import AuditRecord
from lexecon.enforcement.decision import Decision, DecisionType


@pytest.fixture
def temp_ledger(tmp_path):
    signer = Signer(key_dir=tmp_path / "keys")
    return Ledger(ledger_path=tmp_path / "ledger.jsonl", signer=signer)


def test_ledger_first_record_genesis(temp_ledger):
    """First record must have previous_hash == 'GENESIS'."""
    decision = Decision(DecisionType.ALLOW, "test", "test-policy")
    record = temp_ledger.write_record({"tool": "shell.run", "args": {"executable": "ls", "args": []}}, decision)
    assert record.previous_hash == "GENESIS"


def test_ledger_second_record_links_first(temp_ledger):
    """Second record's previous_hash must equal first record's record_hash."""
    decision = Decision(DecisionType.ALLOW, "test", "test-policy")
    r1 = temp_ledger.write_record({"tool": "shell.run", "args": {"executable": "ls", "args": []}}, decision)
    r2 = temp_ledger.write_record({"tool": "shell.run", "args": {"executable": "pwd", "args": []}}, decision)
    assert r2.previous_hash == r1.record_hash


def test_ledger_hash_chain_valid(temp_ledger):
    """Multiple records must form a valid hash chain."""
    decision = Decision(DecisionType.ALLOW, "test", "test-policy")
    records = []
    for i in range(5):
        tool_call = {"tool": "shell.run", "args": {"executable": "echo", "args": [f"cmd{i}"]}}
        record = temp_ledger.write_record(tool_call, decision)
        records.append(record)

    # Verify chain
    for i in range(1, len(records)):
        assert records[i].previous_hash == records[i - 1].record_hash


def test_ledger_hash_is_deterministic(temp_ledger):
    """Same record data must produce the same hash."""
    decision = Decision(DecisionType.ALLOW, "test", "test-policy")
    tool_call = {"tool": "shell.run", "args": {"executable": "echo", "args": ["test"]}}

    r1 = temp_ledger.write_record(tool_call, decision)

    # Read back and recompute hash
    data = {
        "record_id": r1.record_id,
        "timestamp": r1.timestamp,
        "tool_name": r1.tool_name,
        "tool_args_hash": r1.tool_args_hash,
        "decision": r1.decision,
        "reason": r1.reason,
        "policy_id": r1.policy_id,
        "previous_hash": r1.previous_hash,
    }
    recomputed = AuditRecord.compute_record_hash(data)
    assert r1.record_hash == recomputed


def test_ledger_does_not_store_raw_args(temp_ledger):
    """Audit record must not contain raw tool args, only hash."""
    decision = Decision(DecisionType.ALLOW, "test", "test-policy")
    tool_call = {"tool": "shell.run", "args": {"executable": "echo", "args": ["secret_password"]}}
    record = temp_ledger.write_record(tool_call, decision)

    assert record.tool_args_hash != ""
    assert "secret_password" not in record.tool_args_hash  # it's a hash, not the raw value
    # tool_args is not a field on AuditRecord
    assert not hasattr(record, "tool_args")


def test_ledger_append_only(temp_ledger):
    """Writing multiple times must append, not overwrite."""
    decision = Decision(DecisionType.ALLOW, "test", "test-policy")
    for i in range(3):
        tool_call = {"tool": "shell.run", "args": {"executable": "echo", "args": [f"cmd{i}"]}}
        temp_ledger.write_record(tool_call, decision)

    records = temp_ledger.read_all_records()
    assert len(records) == 3


def test_ledger_file_contains_valid_jsonl(temp_ledger):
    """Each line in ledger file must be valid JSON."""
    decision = Decision(DecisionType.BLOCK, "test", "test-policy")
    temp_ledger.write_record({"tool": "shell.run", "args": {"executable": "rm", "args": ["-rf", "/"]}}, decision)

    with open(temp_ledger.ledger_path, "r") as f:
        lines = f.readlines()

    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert "record_id" in parsed
    assert "record_hash" in parsed
    assert "signature" in parsed
    assert parsed["decision"] == "BLOCK"


def test_ledger_read_all_records(temp_ledger):
    """read_all_records must return AuditRecord objects."""
    decision = Decision(DecisionType.ALLOW, "test", "test-policy")
    temp_ledger.write_record({"tool": "shell.run", "args": {"executable": "ls", "args": []}}, decision)
    temp_ledger.write_record({"tool": "shell.run", "args": {"executable": "pwd", "args": []}}, decision)

    records = temp_ledger.read_all_records()
    assert len(records) == 2
    assert isinstance(records[0], AuditRecord)
    assert isinstance(records[1], AuditRecord)
