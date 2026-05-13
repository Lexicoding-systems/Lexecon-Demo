"""Tests for ledger verification."""
import pytest
import json

from lexecon.audit.ledger import Ledger
from lexecon.audit.signer import Signer
from lexecon.audit.verifier import Verifier
from lexecon.audit.record import AuditRecord
from lexecon.enforcement.decision import Decision, DecisionType


@pytest.fixture
def temp_signer_ledger(tmp_path):
    signer = Signer(key_dir=tmp_path / "keys")
    ledger = Ledger(ledger_path=tmp_path / "ledger.jsonl", signer=signer)
    return signer, ledger


def test_verifier_valid_ledger(temp_signer_ledger):
    """A valid unmodified ledger must pass verification."""
    signer, ledger = temp_signer_ledger
    decision = Decision(DecisionType.BLOCK, "test", "test-policy")
    ledger.write_record({"tool": "shell.run", "args": {"executable": "rm", "args": ["-rf", "/"]}}, decision)

    verifier = Verifier(signer=signer)
    result = verifier.verify_ledger(ledger.ledger_path)
    assert result["valid"] is True
    assert result["record_count"] == 1
    assert result["errors"] == []


def test_verifier_detects_tampering(temp_signer_ledger):
    """Modifying a record's decision must cause verification to fail."""
    signer, ledger = temp_signer_ledger
    decision = Decision(DecisionType.BLOCK, "test", "test-policy")
    ledger.write_record({"tool": "shell.run", "args": {"executable": "rm", "args": ["-rf", "/"]}}, decision)

    # Tamper with the ledger file
    with open(ledger.ledger_path, "r") as f:
        line = f.readline()
    record = json.loads(line)
    record["decision"] = "ALLOW"  # Change BLOCK to ALLOW
    # Don't recompute hash — this is the tampering

    with open(ledger.ledger_path, "w") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")

    verifier = Verifier(signer=signer)
    result = verifier.verify_ledger(ledger.ledger_path)
    assert result["valid"] is False
    assert any("hash mismatch" in e for e in result["errors"])


def test_verifier_detects_modified_signature(temp_signer_ledger):
    """Modifying a signature must cause verification to fail."""
    signer, ledger = temp_signer_ledger
    decision = Decision(DecisionType.BLOCK, "test", "test-policy")
    ledger.write_record({"tool": "shell.run", "args": {"executable": "rm", "args": ["-rf", "/"]}}, decision)

    with open(ledger.ledger_path, "r") as f:
        line = f.readline()
    record = json.loads(line)
    record["signature"] = "a" * 88  # Invalid signature

    with open(ledger.ledger_path, "w") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")

    verifier = Verifier(signer=signer)
    result = verifier.verify_ledger(ledger.ledger_path)
    assert result["valid"] is False
    assert any("signature invalid" in e for e in result["errors"])


def test_verifier_detects_reordered_records(temp_signer_ledger):
    """Reordering records must break the previous_hash chain."""
    signer, ledger = temp_signer_ledger
    decision = Decision(DecisionType.ALLOW, "test", "test-policy")
    r1 = ledger.write_record({"tool": "shell.run", "args": {"executable": "echo", "args": ["cmd1"]}}, decision)
    r2 = ledger.write_record({"tool": "shell.run", "args": {"executable": "echo", "args": ["cmd2"]}}, decision)

    # Read both records
    records = ledger.read_all_records()

    # Swap order and rewrite
    swapped = [records[1], records[0]]  # r2 first, r1 second
    with open(ledger.ledger_path, "w") as f:
        for r in swapped:
            f.write(json.dumps(r.__dict__, sort_keys=True) + "\n")

    verifier = Verifier(signer=signer)
    result = verifier.verify_ledger(ledger.ledger_path)
    assert result["valid"] is False
    assert any("chain broken" in e for e in result["errors"])


def test_verifier_detects_modified_hash(temp_signer_ledger):
    """Modifying a record_hash must cause verification to fail."""
    signer, ledger = temp_signer_ledger
    decision = Decision(DecisionType.BLOCK, "test", "test-policy")
    ledger.write_record({"tool": "shell.run", "args": {"executable": "rm", "args": ["-rf", "/"]}}, decision)

    with open(ledger.ledger_path, "r") as f:
        line = f.readline()
    record = json.loads(line)
    record["record_hash"] = "tamperedhash123"

    with open(ledger.ledger_path, "w") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")

    verifier = Verifier(signer=signer)
    result = verifier.verify_ledger(ledger.ledger_path)
    assert result["valid"] is False
    assert any("hash mismatch" in e for e in result["errors"])


def test_verifier_with_explicit_public_key_path(tmp_path):
    """Verifier constructed with an explicit public key path validates a valid ledger."""
    key_dir = tmp_path / "keys"
    signer = Signer(key_dir=key_dir)
    ledger = Ledger(ledger_path=tmp_path / "ledger.jsonl", signer=signer)
    decision = Decision(DecisionType.BLOCK, "test", "test-policy")
    ledger.write_record({"tool": "shell.run", "args": {"executable": "rm", "args": ["-rf", "/"]}}, decision)

    # Third-party verifier uses only the exported public key file
    third_party_signer = Signer(public_key_path=key_dir / "public_key.pem")
    verifier = Verifier(signer=third_party_signer)
    result = verifier.verify_ledger(ledger.ledger_path)
    assert result["valid"] is True
    assert result["record_count"] == 1


def test_verifier_with_wrong_public_key_fails(tmp_path):
    """Verifier with a mismatched public key must report signature invalid."""
    key_dir_a = tmp_path / "keys_a"
    key_dir_b = tmp_path / "keys_b"
    signer_a = Signer(key_dir=key_dir_a)
    signer_b = Signer(key_dir=key_dir_b)

    # Write ledger signed by signer_a
    ledger = Ledger(ledger_path=tmp_path / "ledger.jsonl", signer=signer_a)
    decision = Decision(DecisionType.BLOCK, "test", "test-policy")
    ledger.write_record({"tool": "shell.run", "args": {"executable": "rm", "args": ["-rf", "/"]}}, decision)

    # Attempt to verify using signer_b's public key
    _ = signer_b.public_key  # ensure key_b files exist
    wrong_signer = Signer(public_key_path=key_dir_b / "public_key.pem")
    verifier = Verifier(signer=wrong_signer)
    result = verifier.verify_ledger(ledger.ledger_path)
    assert result["valid"] is False
    assert any("signature invalid" in e for e in result["errors"])
