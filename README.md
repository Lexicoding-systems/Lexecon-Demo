# Lexecon Core

Runtime enforcement layer for AI agent tool calls. Lexecon intercepts proposed tool calls before execution, evaluates them against deterministic policy, returns `ALLOW` / `BLOCK` / `ESCALATE`, writes a cryptographically verifiable audit record, and prevents unsafe actions from executing.

## What It Does

Lexecon sits between an AI agent and the tools it wants to use. Before any tool executes:

1. The proposed tool call is submitted to Lexecon
2. A deterministic policy engine evaluates the call (no LLM involved)
3. Dangerous patterns are blocked
4. Every decision is written to a signed, hash-chained audit ledger
5. Blocked commands **never execute**

## Architecture

```
lexecon/
  enforcement/          # Policy evaluation and interception
    decision.py         # DecisionType enum, Decision dataclass
    policy_engine.py    # YAML policy loading, deterministic evaluation
    interceptor.py      # Tool call interception, execution gate
  tools/                # Executable tool wrappers
    shell.py            # subprocess.run wrapper (shell commands)
  audit/                # Audit records, ledger, signing, verification
    record.py           # AuditRecord dataclass, SHA-256 hashing
    ledger.py           # Append-only JSONL ledger with hash chaining
    signer.py           # Ed25519 key generation and signing
    verifier.py         # Ledger verification (hash chain + signatures)
  policies/
    default_policy.yaml # Blocking rules for dangerous shell commands
  cli.py                # Typer CLI (init-keys, demo, verify)
```

## Security Model

Lexecon enforces a **fail-closed** model:

- Any failure in policy evaluation → `BLOCK`
- Any failure in audit writing → `BLOCK`
- Any failure in signing → `BLOCK`
- Blocked commands **never execute**
- Raw tool arguments are **never stored** in audit records (only SHA-256 hashes)
- Audit records are **hash-chained** and **signed with Ed25519**
- Ledger tampering is **detected** by independent verification

## Installation

```bash
pip install -e ".[dev]"
```

## Quick Start

```bash
# Initialize Ed25519 signing keys
lexecon init-keys

# Run the demo (attempts a destructive command, shows it being blocked)
lexecon demo

# Verify the audit ledger
lexecon verify .audit/ledger.jsonl
```

### Demo Output

```
Attempted tool call: shell.run
Decision: BLOCK
Reason: Destructive shell command detected.
Executed: false
Audit record written: true
Ledger verification: valid
```

## Running Tests

```bash
pytest
```

46 tests covering policy evaluation, interception, audit ledger, signing, verification, and end-to-end demo flow.

## CLI Commands

### `lexecon init-keys`

Generate an Ed25519 keypair for signing audit records. Keys are stored in `.lexecon/` (automatically gitignored).

### `lexecon demo`

Run the blocking demo:
1. Initialize keys if missing
2. Attempt `rm -rf ./important_data` through the interceptor
3. Show decision, reason, execution status, and ledger verification

### `lexecon verify <path>`

Verify an audit ledger file:
- Independently recalculates every record's hash
- Confirms the `previous_hash` chain
- Verifies Ed25519 signatures
- Reports `VALID` or `INVALID` with specific errors

## Default Policy

The default policy blocks these dangerous shell command patterns:

| Pattern | Example Match |
|---------|--------------|
| `rm -rf` | `rm -rf /important_data` |
| `sudo rm` | `sudo rm -rf /etc` |
| `mkfs` | `mkfs.ext4 /dev/sda1` |
| `diskutil erase` | `diskutil eraseDisk JHFS+ NewDisk /dev/disk1` |

Policy is deterministic YAML — no LLM is used for evaluation.

## How It Works

### Interception Flow

```
Proposed tool call
  → Interceptor.intercept()
    → PolicyEngine.evaluate()     # Deterministic pattern matching
      → Decision: BLOCK / ALLOW / ESCALATE
    → Ledger.write_record()       # Hash, sign, append to JSONL
    → if ALLOW: execute tool
    → if BLOCK: return without executing
```

### Audit Ledger Format

Each line in `.audit/ledger.jsonl` is a JSON record:

```json
{
  "record_id": "<uuid>",
  "timestamp": "2026-01-01T00:00:00+00:00",
  "tool_name": "shell.run",
  "tool_args_hash": "<sha-256-of-canonical-json>",
  "decision": "BLOCK",
  "reason": "Destructive shell command detected.",
  "policy_id": "block_destructive_shell",
  "previous_hash": "GENESIS",
  "record_hash": "<sha-256-of-record-data>",
  "signature": "<ed25519-signature-base64>"
}
```

- First record has `previous_hash: "GENESIS"`
- Each subsequent record links to the previous record's `record_hash`
- Every record is signed with Ed25519

### Verification

The verifier independently:
1. Recalculates each record's SHA-256 hash
2. Confirms the `previous_hash` chain is unbroken
3. Verifies the Ed25519 signature on each record
4. Detects edited records, reordered records, and missing records

## Project Structure

```
lexecon-core/
  README.md
  LICENSE
  pyproject.toml
  .gitignore
  .env.example
  SECURITY_REVIEW_REPORT.md
  lexecon/
    __init__.py
    enforcement/
      __init__.py
      decision.py
      interceptor.py
      policy_engine.py
    tools/
      __init__.py
      shell.py
    audit/
      __init__.py
      record.py
      ledger.py
      signer.py
      verifier.py
    policies/
      __init__.py
      default_policy.yaml
    cli.py
  examples/
    block_destructive_shell.py
  tests/
    test_policy_engine.py
    test_interceptor.py
    test_audit_ledger.py
    test_signer.py
    test_verifier.py
    test_demo_flow.py
```

## License

MIT
