"""Audit record model for Lexecon."""
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class AuditRecord:
    """A single audit record for a tool call decision."""
    record_id: str
    timestamp: str
    tool_name: str
    tool_args_hash: str
    decision: str
    reason: str
    policy_id: str
    previous_hash: str
    record_hash: str = ""
    signature: str = ""

    @staticmethod
    def hash_tool_args(tool_args: dict) -> str:
        """SHA-256 of canonical JSON of tool args."""
        canonical = json.dumps(tool_args, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def compute_record_hash(record_data: dict) -> str:
        """
        Compute SHA-256 hash of the record.
        Exclude 'record_hash' and 'signature' fields.
        Use canonical JSON representation (sorted keys).
        """
        data = {k: v for k, v in record_data.items() if k not in ("record_hash", "signature")}
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
