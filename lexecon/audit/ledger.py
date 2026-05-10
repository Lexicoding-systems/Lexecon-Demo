"""Append-only JSONL ledger with hash chaining."""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .record import AuditRecord
from .signer import Signer

DEFAULT_LEDGER_PATH = Path(".audit/ledger.jsonl")


class Ledger:
    """Append-only JSONL ledger with hash chaining."""

    def __init__(self, ledger_path: Path | None = None, signer: Signer | None = None):
        self.ledger_path = Path(ledger_path) if ledger_path else DEFAULT_LEDGER_PATH
        self.signer = signer or Signer()

    def get_last_hash(self) -> str:
        """Return the record_hash of the last entry, or 'GENESIS' if empty."""
        if not self.ledger_path.exists():
            return "GENESIS"
        with open(self.ledger_path, "r") as f:
            lines = f.readlines()
        if not lines:
            return "GENESIS"
        last_record = json.loads(lines[-1])
        return last_record.get("record_hash", "GENESIS")

    def write_record(self, tool_call: dict, decision) -> AuditRecord:
        """
        Create, sign, and append an audit record.
        """
        from lexecon.enforcement.decision import Decision, DecisionType

        record = AuditRecord(
            record_id=uuid.uuid4().hex,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tool_name=tool_call.get("tool", ""),
            tool_args_hash=AuditRecord.hash_tool_args(tool_call.get("args", {})),
            decision=decision.decision.value,
            reason=decision.reason,
            policy_id=decision.policy_id,
            previous_hash=self.get_last_hash(),
        )

        # Compute hash
        record_dict = record.__dict__.copy()
        record.record_hash = AuditRecord.compute_record_hash(record_dict)

        # Sign
        record.signature = self.signer.sign(record.record_hash)

        # Append to JSONL
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ledger_path, "a") as f:
            f.write(json.dumps(record.__dict__, sort_keys=True, separators=(",", ":")) + "\n")

        return record

    def read_all_records(self) -> list[AuditRecord]:
        """Read all records from JSONL file."""
        records = []
        if not self.ledger_path.exists():
            return records
        with open(self.ledger_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    records.append(AuditRecord(**data))
        return records
