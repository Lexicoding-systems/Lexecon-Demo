"""Ledger verification: hash chain + Ed25519 signatures."""
from pathlib import Path

from .record import AuditRecord
from .signer import Signer


class Verifier:
    """Verify ledger integrity: hash chain + Ed25519 signatures."""

    def __init__(self, signer: Signer | None = None):
        self.signer = signer or Signer()

    def verify_ledger(self, ledger_path: Path) -> dict:
        """
        Load ledger, recalculate hashes, confirm chain, verify signatures.
        Returns {"valid": bool, "record_count": int, "errors": list[str]}.
        """
        import json

        errors = []

        if not ledger_path.exists():
            return {"valid": False, "record_count": 0, "errors": ["Ledger file not found."]}

        records = []
        with open(ledger_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))

        for i, record in enumerate(records):
            # 1. Recalculate hash
            recalculated = AuditRecord.compute_record_hash(record)
            if recalculated != record.get("record_hash", ""):
                errors.append(f"Record {i}: hash mismatch")

            # 2. Check previous_hash chain
            if i == 0:
                if record.get("previous_hash") != "GENESIS":
                    errors.append(f"Record {i}: first record previous_hash must be GENESIS")
            else:
                expected_previous = records[i - 1].get("record_hash", "")
                if record.get("previous_hash") != expected_previous:
                    errors.append(f"Record {i}: previous_hash chain broken")

            # 3. Verify Ed25519 signature
            record_hash = record.get("record_hash", "")
            signature = record.get("signature", "")
            if not self.signer.verify(record_hash, signature):
                errors.append(f"Record {i}: signature invalid")

        return {
            "valid": len(errors) == 0,
            "record_count": len(records),
            "errors": errors,
        }
