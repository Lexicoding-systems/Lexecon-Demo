# Lexecon Core — MVP Specification

## 1. Overview

Lexecon Core is a **runtime enforcement layer** for AI agent tool calls. It intercepts proposed tool calls before execution, evaluates them against a deterministic policy, returns `ALLOW` / `BLOCK` / `ESCALATE`, writes a cryptographically verifiable audit record, and prevents unsafe actions from executing.

This MVP proves one narrow flow:
1. A proposed shell command is submitted.
2. Lexecon intercepts it before execution.
3. A deterministic policy engine evaluates the command.
4. Dangerous commands are blocked.
5. Blocked commands never execute.
6. Every decision writes an audit record.
7. Audit records are hash-chained.
8. Audit records are signed with Ed25519.
9. A verifier can validate the ledger.
10. Tampering causes verification to fail.

## 2. Architecture

### 2.1 Module Boundaries

```
lexecon/
├── enforcement/          # Policy evaluation and interception
│   ├── decision.py       # DecisionType enum, Decision dataclass
│   ├── policy_engine.py  # YAML policy loading, deterministic evaluation
│   └── interceptor.py    # Tool call interception, execution gate
├── tools/                # Executable tool wrappers
│   └── shell.py          # shell_run wrapper (subprocess)
├── audit/                # Audit records, ledger, signing, verification
│   ├── record.py         # AuditRecord dataclass, hashing
│   ├── ledger.py         # JSONL ledger, append-only, hash chain
│   ├── signer.py         # Ed25519 key generation, signing
│   └── verifier.py       # Ledger verification (chain + signatures)
├── policies/
│   └── default_policy.yaml  # Default blocking rules
└── cli.py                # Typer CLI (init-keys, demo, verify)
```

### 2.2 Data Flow

```
Proposed Tool Call
    → interceptor.intercept(tool_call)
        → policy_engine.evaluate(tool_call)
            → Decision (ALLOW / BLOCK / ESCALATE)
        → audit.ledger.write_record(tool_call, decision)
            → AuditRecord (with hash, signature, chain)
        → IF ALLOW: tools.shell.shell_run(command)
        → Return structured result
```

### 2.3 Core Invariants

1. **No tool call may execute before Lexecon makes a policy decision.**
2. **If policy evaluation fails, signing fails, audit writing fails, or enforcement fails, the system must fail closed and block execution.**
3. **Blocked tool calls must never execute.**
4. **Every attempted tool call produces an audit record, including blocked calls.**

## 3. Detailed Specifications

### 3.1 Enforcement Layer (`lexecon/enforcement/`)

#### 3.1.1 `decision.py`

```python
from enum import Enum
from dataclasses import dataclass

class DecisionType(Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"

@dataclass
class Decision:
    decision: DecisionType
    reason: str
    policy_id: str

    @property
    def allowed(self) -> bool:
        return self.decision == DecisionType.ALLOW
```

#### 3.1.2 `policy_engine.py`

```python
import yaml
from pathlib import Path
from typing import Any

from .decision import Decision, DecisionType

class PolicyEngine:
    """Deterministic policy evaluation. Never uses LLM."""

    def __init__(self, policy_path: Path | None = None):
        """Load policy from YAML. If no path provided, use default."""
        ...

    def evaluate(self, tool_call: dict[str, Any]) -> Decision:
        """
        Evaluate a tool call against loaded policy rules.
        Returns BLOCK if any dangerous pattern matches.
        Returns ALLOW if no blocking rule applies.
        Returns BLOCK (fail-closed) if evaluation raises an exception.
        """
        ...
```

**Rule matching logic:**
1. For each rule in policy:
   - Check if `tool_call["tool"]` matches `rule.tool` (exact match)
   - If tool matches, check if any pattern in `rule.patterns` is a substring of the command argument
   - If pattern matches → return `Decision(BLOCK, rule.reason, rule.id)`
2. If no rules match → return `Decision(ALLOW, "No blocking rule matched.", "default")`
3. If evaluation raises any exception → return `Decision(BLOCK, f"Policy evaluation error: {exc}", "error")`

#### 3.1.3 `interceptor.py`

```python
from typing import Any

from .decision import Decision
from .policy_engine import PolicyEngine
from ..audit.ledger import Ledger

class Interceptor:
    """Intercepts tool calls, evaluates policy, gates execution."""

    def __init__(self, policy_engine: PolicyEngine, ledger: Ledger):
        ...

    def intercept(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        """
        1. Evaluate tool_call through PolicyEngine.
        2. Write audit record for every decision.
        3. Execute only if decision is ALLOW.
        4. Never execute if decision is BLOCK or ESCALATE.
        5. Return structured output.
        """
        ...
```

**Return format:**
```python
{
    "decision": "BLOCK",           # DecisionType value as string
    "executed": False,             # bool
    "tool_result": None,           # dict or None (only if executed)
    "audit_record_id": "...",      # str
    "reason": "...",               # str
}
```

**Execution flow:**
1. Call `policy_engine.evaluate(tool_call)` → Decision
2. Call `ledger.write_record(tool_call, decision)` → AuditRecord
3. If `decision.allowed` → call tool executor → tool_result
4. If NOT `decision.allowed` → tool_result = None
5. Return structured dict

### 3.2 Policy File (`lexecon/policies/default_policy.yaml`)

```yaml
rules:
  - id: block_destructive_shell
    tool: shell.run
    action: BLOCK
    patterns:
      - "rm -rf"
      - "sudo rm"
      - "mkfs"
      - "diskutil erase"
    reason: "Destructive shell command detected."
```

### 3.3 Tools Layer (`lexecon/tools/`)

#### 3.3.1 `shell.py`

```python
import subprocess

def shell_run(command: str, timeout: int = 10) -> dict[str, Any]:
    """
    Execute a shell command via subprocess.
    Returns structured output. Does NOT call policy engine.
    The caller (Interceptor) is responsible for policy gating.
    """
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }
```

### 3.4 Audit Layer (`lexecon/audit/`)

#### 3.4.1 `record.py`

```python
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

@dataclass
class AuditRecord:
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
        ...

    @staticmethod
    def compute_record_hash(record_data: dict) -> str:
        """
        Compute SHA-256 hash of the record.
        Exclude 'record_hash' and 'signature' fields from the hash input.
        Use canonical JSON representation (sorted keys).
        """
        ...
```

**Record creation:**
- `record_id`: `uuid.uuid4().hex`
- `timestamp`: `datetime.now(timezone.utc).isoformat()`
- `tool_name`: `tool_call["tool"]`
- `tool_args_hash`: `hash_tool_args(tool_call.get("args", {}))`
- `decision`: `decision.decision.value` (DecisionType string)
- `reason`: `decision.reason`
- `policy_id`: `decision.policy_id`
- `previous_hash`: hash of previous record, or "GENESIS" for first record
- `record_hash`: computed AFTER all other fields are set (excluding record_hash and signature)
- `signature`: added by signer AFTER hash is computed

**Important:** Do NOT store raw tool args in the audit record. Only store the hash.

#### 3.4.2 `ledger.py`

```python
from pathlib import Path
from typing import Optional

from .record import AuditRecord
from .signer import Signer

class Ledger:
    """Append-only JSONL ledger with hash chaining."""

    def __init__(self, ledger_path: Path | None = None, signer: Signer | None = None):
        """
        Default path: .audit/ledger.jsonl
        Creates directories if needed.
        """
        ...

    def get_last_hash(self) -> str:
        """Return the record_hash of the last entry, or 'GENESIS' if empty."""
        ...

    def write_record(self, tool_call: dict, decision: Decision) -> AuditRecord:
        """
        1. Create AuditRecord.
        2. Set previous_hash from last record or GENESIS.
        3. Compute record_hash.
        4. Sign record_hash.
        5. Append to JSONL file.
        6. Return record.
        """
        ...

    def read_all_records(self) -> list[AuditRecord]:
        """Read all records from JSONL file."""
        ...
```

**Ledger format:**
- One JSON object per line (JSONL)
- Append-only — never modify existing lines
- First record has `"previous_hash": "GENESIS"`
- Each subsequent record has `"previous_hash"` equal to `"record_hash"` of previous record
- Directory `.audit/` must be gitignored

#### 3.4.3 `signer.py`

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from pathlib import Path
import base64

class Signer:
    """Ed25519 key generation, signing, and verification."""

    def __init__(self, key_dir: Path | None = None):
        """
        Default key_dir: .lexecon/
        Generates keypair if keys don't exist.
        """
        ...

    @property
    def private_key(self) -> Ed25519PrivateKey:
        """Load or generate private key."""
        ...

    @property
    def public_key(self) -> Ed25519PublicKey:
        """Derive public key from private key."""
        ...

    def sign(self, message: bytes | str) -> str:
        """
        Sign message with Ed25519 private key.
        Return base64-encoded signature string.
        """
        ...

    def verify(self, message: bytes | str, signature: str) -> bool:
        """
        Verify signature with Ed25519 public key.
        Return True if valid, False if invalid.
        """
        ...
```

**Key storage:**
- Private key: `.lexecon/private_key.pem` (PEM format, encrypted)
- Public key: `.lexecon/public_key.pem` (PEM format)
- Directory `.lexecon/` must be gitignored
- Never hardcode keys

#### 3.4.4 `verifier.py`

```python
from pathlib import Path
from typing import Optional

from .ledger import Ledger
from .record import AuditRecord
from .signer import Signer

class Verifier:
    """Verify ledger integrity: hash chain + Ed25519 signatures."""

    def __init__(self, signer: Signer | None = None):
        ...

    def verify_ledger(self, ledger_path: Path) -> dict[str, Any]:
        """
        1. Load all records from JSONL.
        2. Recalculate each record's hash.
        3. Confirm previous_hash chain.
        4. Verify Ed25519 signature.
        5. Return verification result.

        Returns:
            {
                "valid": bool,
                "record_count": int,
                "errors": list[str],  # empty if valid
            }
        """
        ...
```

**Verification checks:**
1. For each record, independently recalculate `record_hash` from all fields except `record_hash` and `signature`
2. Compare recalculated hash with stored `record_hash` → if different, tampering detected
3. Verify `previous_hash` chain: first record must have `previous_hash == "GENESIS"`, subsequent records must have `previous_hash == previous_record.record_hash`
4. Verify Ed25519 signature of `record_hash` using public key
5. Detect: edited records (hash mismatch), reordered records (chain break), missing records (chain break)

### 3.5 CLI (`lexecon/cli.py`)

```python
import typer

app = typer.Typer(name="lexecon")

@app.command()
def init_keys():
    """Initialize local Ed25519 keypair."""
    ...

@app.command()
def demo():
    """
    Run the demo:
    1. Initialize keys if missing.
    2. Attempt a destructive shell command through the interceptor.
    3. Print results.
    """
    ...

@app.command()
def verify(path: str):
    """Verify an audit ledger at the given path."""
    ...
```

**`lexecon demo` output:**
```
Attempted tool call: shell.run
Decision: BLOCK
Reason: Destructive shell command detected.
Executed: false
Audit record written: true
Ledger verification: valid
```

**`lexecon verify PATH` output (valid):**
```
Ledger: .audit/ledger.jsonl
Records: 1
Status: VALID
```

**`lexecon verify PATH` output (invalid):**
```
Ledger: .audit/ledger.jsonl
Records: 1
Status: INVALID
Errors:
  - Record 0: hash mismatch
  - Record 1: previous_hash chain broken
```

### 3.6 Example Script (`examples/block_destructive_shell.py`)

```python
#!/usr/bin/env python3
"""
Demo: Block a destructive shell command through Lexecon.
"""
import sys
from pathlib import Path

# Add lexecon to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from lexecon.enforcement.interceptor import Interceptor
from lexecon.enforcement.policy_engine import PolicyEngine
from lexecon.audit.ledger import Ledger
from lexecon.audit.signer import Signer

def main():
    # Initialize components
    signer = Signer()
    ledger = Ledger(signer=signer)
    policy_engine = PolicyEngine()
    interceptor = Interceptor(policy_engine, ledger)

    # Attempt a destructive command
    tool_call = {
        "tool": "shell.run",
        "args": {"command": "rm -rf ./important_data"},
    }

    result = interceptor.intercept(tool_call)

    print(f"Decision: {result['decision']}")
    print(f"Reason: {result['reason']}")
    print(f"Executed: {result['executed']}")

if __name__ == "__main__":
    main()
```

## 4. Test Specifications

### 4.1 `tests/test_policy_engine.py`

```python
def test_policy_blocks_rm_rf():
    """Policy engine must BLOCK rm -rf command."""
    ...

def test_policy_blocks_sudo_rm():
    """Policy engine must BLOCK sudo rm command."""
    ...

def test_policy_blocks_mkfs():
    """Policy engine must BLOCK mkfs command."""
    ...

def test_policy_allows_safe_command():
    """Policy engine must ALLOW safe commands like ls."""
    ...

def test_policy_allows_echo():
    """Policy engine must ALLOW echo command."""
    ...

def test_policy_fail_closed():
    """If policy evaluation raises an exception, return BLOCK."""
    ...
```

### 4.2 `tests/test_interceptor.py`

```python
def test_interceptor_never_executes_blocked_tool():
    """
    MOST IMPORTANT TEST.
    When policy returns BLOCK, the tool must NEVER execute.
    Use monkeypatching to prove shell_run was not called.
    """
    ...

def test_interceptor_executes_allowed_tool():
    """When policy returns ALLOW, the tool must execute and return result."""
    ...

def test_blocked_call_returns_correct_structure():
    """Blocked call must return structured output with all fields."""
    ...

def test_audit_record_written_for_blocked_call():
    """Every blocked call must produce an audit record."""
    ...

def test_audit_record_written_for_allowed_call():
    """Every allowed call must produce an audit record."""
    ...

def test_interceptor_fail_closed_on_exception():
    """If interceptor raises, it must not allow execution."""
    ...
```

### 4.3 `tests/test_audit_ledger.py`

```python
def test_ledger_hash_chain_valid():
    """Multiple records must form a valid hash chain."""
    ...

def test_ledger_first_record_genesis():
    """First record must have previous_hash == 'GENESIS'."""
    ...

def test_ledger_second_record_links_first():
    """Second record's previous_hash must equal first record's record_hash."""
    ...

def test_ledger_hash_is_deterministic():
    """Same record data must produce the same hash."""
    ...

def test_ledger_does_not_store_raw_args():
    """Audit record must not contain raw tool args, only hash."""
    ...

def test_ledger_append_only(tmp_path):
    """Writing multiple times must append, not overwrite."""
    ...
```

### 4.4 `tests/test_signer.py`

```python
def test_key_generation_creates_files():
    """Signer must generate key files if they don't exist."""
    ...

def test_signature_verifies():
    """A valid signature must verify correctly."""
    ...

def test_signature_fails_if_record_modified():
    """Modifying the message after signing must fail verification."""
    ...

def test_signature_is_base64():
    """Signature string must be valid base64."""
    ...
```

### 4.5 `tests/test_verifier.py`

```python
def test_verifier_valid_ledger():
    """A valid unmodified ledger must pass verification."""
    ...

def test_verifier_detects_tampering():
    """Modifying a record's decision must cause verification to fail."""
    ...

def test_verifier_detects_reordered_records():
    """Reordering records must break the previous_hash chain."""
    ...

def test_verifier_detects_missing_record():
    """Removing a record must break the previous_hash chain."""
    ...

def test_verifier_detects_modified_signature():
    """Modifying a signature must cause verification to fail."""
    ...

def test_verifier_detects_modified_hash():
    """Modifying a record_hash must cause verification to fail."""
    ...
```

### 4.6 `tests/test_demo_flow.py`

```python
def test_demo_flow_blocks_destructive_command():
    """
    End-to-end: destructive command is blocked, does not execute,
    audit record is written, ledger verifies.
    """
    ...
```

## 5. Configuration

### 5.1 `pyproject.toml`

```toml
[project]
name = "lexecon-core"
version = "0.1.0"
description = "Runtime enforcement layer for AI agent tool calls"
requires-python = ">=3.11"
dependencies = [
    "pyyaml>=6.0",
    "cryptography>=42.0.0",
    "typer>=0.12.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
]

[project.scripts]
lexecon = "lexecon.cli:app"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

### 5.2 `.gitignore`

```
__pycache__/
*.pyc
*.pyo
.venv/
.env
.audit/
.lexecon/
*.egg-info/
dist/
build/
```

### 5.3 `.env.example`

```
# Lexecon Core — Environment Configuration
# Copy to .env and customize as needed
# LEXECON_POLICY_PATH=custom_policy.yaml
# LEXECON_LEDGER_PATH=.audit/ledger.jsonl
# LEXECON_KEY_DIR=.lexecon/
```

## 6. Security Invariants (for Review)

1. **Tool execution ordering**: No tool executes before policy decision.
2. **Blocked execution**: Blocked commands never execute.
3. **Fail-closed policy**: Policy failure must become BLOCK, not ALLOW.
4. **Audit failure handling**: Audit writing failure must not be silently ignored.
5. **Signing failure handling**: Signing failure must not be silently ignored.
6. **Arg storage**: Raw tool args must NOT be stored in audit records (only hash).
7. **Key safety**: Private keys must not be committed or hardcoded.
8. **Tamper detection**: Ledger tampering must cause verification to fail.
9. **Independent verification**: Verifier must independently recalculate hashes.
10. **Fail-closed system**: Any failure must result in BLOCK behavior.

## 7. Out of Scope (MVP)

- Dashboard or web UI
- SaaS features
- Cloud deployment
- Authentication/authorization
- OpenAI/Anthropic/LangChain adapters
- Complex policy language (DSL)
- Database
- Web server
- Async orchestration
- External agent frameworks
