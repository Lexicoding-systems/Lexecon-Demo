# Lexecon Core

Lexecon is **execution control for AI agents**.

It intercepts agent tool calls before execution, enforces deterministic policy, and writes a cryptographically verifiable decision trail.

## What This Demo Proves

This repository proves one narrow workflow end to end:

1. An agent attempts a tool call (`shell.run`).
2. Lexecon intercepts it before execution.
3. Policy returns `ALLOW`, `BLOCK`, or `ESCALATE`.
4. Lexecon writes a signed, hash-chained audit record.
5. Blocked calls do not execute.
6. An offline verifier can detect audit tampering.

## What This Demo Does **Not** Prove Yet

- Sandboxed operating-system isolation.
- Enterprise key management (HSM/KMS).
- Distributed transparency logs or remote attestation.
- Complete command parsing resistant to advanced obfuscation.

## Quick Start

```bash
pip install -e ".[dev]"
lexecon init-keys
lexecon demo
lexecon verify .audit/ledger.jsonl
```

The `demo` command attempts:

```bash
rm -rf ./important_data
```

Expected result: `Decision: BLOCK`, `Executed: false`, and `Ledger verification: valid`.

## CLI

### `lexecon init-keys`

Creates local Ed25519 keys in `.lexecon/`:

- `private_key.pem`
- `public_key.pem`

### `lexecon demo`

Runs the narrow destructive-command demo through the full interceptor path.

### `lexecon verify <ledger-path>`

Verifies the ledger by checking:

1. Record hash recomputation.
2. `previous_hash` chain continuity.
3. Ed25519 signatures.

Outputs `Status: VALID` or `Status: INVALID` with per-record errors.

## Install and Test

```bash
pip install -e ".[dev]"
pytest
```

Current suite: **44 tests**.

## Repository Map

```text
lexecon/
  cli.py                     # CLI entrypoints: init-keys, demo, verify
  enforcement/
    policy_engine.py         # Deterministic YAML policy evaluation
    interceptor.py           # Enforcement boundary: decision -> audit -> optional execution
    decision.py              # Decision model (ALLOW/BLOCK/ESCALATE)
  tools/
    shell.py                 # shell.run wrapper used only after ALLOW
  audit/
    record.py                # Canonical record schema + hashing helpers
    ledger.py                # Append-only JSONL writing + hash chain linkage
    signer.py                # Ed25519 key generation/sign/verify
    verifier.py              # Offline ledger integrity verification
  policies/
    default_policy.yaml      # Dangerous command blocking patterns
examples/
  block_destructive_shell.py # Scripted demo path
tests/                       # Unit and end-to-end coverage
```

## Threat Model (Demo Scope)

- **Protected asset:** real-world tool execution.
- **Trust boundary:** agent output crossing into tool execution.
- **Control point:** `Interceptor.intercept()`.
- **Audit goal:** prove what was decided and whether the record was modified later.
- **Fail-closed behavior:** interceptor errors return `BLOCK` and prevent execution.

See `SECURITY_REVIEW_REPORT.md` for detailed findings and limitations.

## Files to Inspect First

- `lexecon/enforcement/interceptor.py`
- `lexecon/enforcement/policy_engine.py`
- `lexecon/audit/ledger.py`
- `lexecon/audit/verifier.py`
- `tests/test_demo_flow.py`
- `tests/test_verifier.py`

## License

MIT
