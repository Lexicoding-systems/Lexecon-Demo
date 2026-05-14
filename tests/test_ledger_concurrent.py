"""Tests for concurrent write safety in the Ledger."""
import threading
from lexecon.audit.ledger import Ledger
from lexecon.audit.signer import Signer
from lexecon.audit.verifier import Verifier
from lexecon.enforcement.decision import Decision, DecisionType


def _make_decision(allowed: bool) -> Decision:
    if allowed:
        return Decision(DecisionType.ALLOW, "No blocking rule matched.", "default")
    return Decision(DecisionType.BLOCK, "Blocked.", "block_destructive_shell")


def test_concurrent_writes_produce_valid_chain(tmp_path):
    """
    Concurrent interceptor calls must not break the hash chain.
    Each thread writes N records; the resulting ledger must verify as fully valid.
    """
    keys_dir = tmp_path / "keys"
    ledger_path = tmp_path / "ledger.jsonl"
    signer = Signer(key_dir=keys_dir)
    ledger = Ledger(ledger_path=ledger_path, signer=signer)

    threads = 4
    records_per_thread = 10
    errors: list[Exception] = []

    def write_records():
        try:
            for i in range(records_per_thread):
                tool_call = {"tool": "shell.run", "args": {"executable": "echo", "args": [str(i)]}}
                decision = _make_decision(True)
                ledger.write_record(tool_call, decision)
        except Exception as exc:
            errors.append(exc)

    workers = [threading.Thread(target=write_records) for _ in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()

    assert not errors, f"Threads raised errors: {errors}"

    verifier = Verifier(signer=signer)
    result = verifier.verify_ledger(ledger_path)
    assert result["valid"] is True, f"Chain broken after concurrent writes: {result['errors']}"
    assert result["record_count"] == threads * records_per_thread
