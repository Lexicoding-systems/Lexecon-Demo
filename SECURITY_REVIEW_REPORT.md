# Lexecon Core MVP Security Review Report

**Reviewer:** Lexecon security review pass  
**Scope:** Local Python MVP implementation in `lexecon/`  
**Date:** 2026-05-10  
**Classification:** MVP PASS WITH KNOWN LIMITATIONS

## Executive Summary

The current Lexecon Core MVP satisfies the core enforcement proof:

1. A proposed tool call is evaluated before execution.
2. Destructive `shell.run` commands are blocked.
3. Blocked commands do not execute.
4. Every decision writes an audit record.
5. Audit records are hash-chained.
6. Audit records are signed with Ed25519.
7. Ledger verification detects tampering.

Test status: `46 passed`.

CLI status:

```txt
python -m lexecon.cli demo
Decision: BLOCK
Executed: false
Ledger verification: valid
```

Manual tampering status:

```txt
Status: INVALID
Errors:
  - Record 0: hash mismatch
```

## Security Invariants

| Invariant | Status | Notes |
|---|---:|---|
| No execution before policy decision | PASS | Interceptor evaluates policy first. |
| Blocked command never executes | PASS | Tests monkeypatch `shell_run` and prove it is not called. |
| Unknown tools are not silently executed | PASS | Unsupported tools are blocked by policy and by interceptor defense-in-depth. |
| Malformed input fails closed | PASS | Non-dict calls, missing tool names, missing args, and non-string commands return BLOCK. |
| Audit failure prevents execution | PASS | Interceptor catches failure and returns BLOCK. |
| Signing failure prevents successful record write | PASS | Signing occurs before append. |
| Raw tool args are not persisted | PASS | Ledger stores `tool_args_hash`, not raw args. |
| Ledger tampering is detected | PASS | Recalculated hash mismatch invalidates ledger. |
| Key directory is restricted | PASS | `.lexecon/` is set to `0o700`. |
| Private key file is restricted | PASS | Private key is created with `0o600`. |

## Patches Applied in This Pass

### 1. Unsupported tool fail-closed behavior

Previously, non-shell tools could be treated as outside the shell rule namespace. The MVP now blocks unsupported tools by default.

```txt
Unsupported tool for MVP: <tool_name>
```

### 2. Malformed shell call fail-closed behavior

`shell.run` calls without valid dict args or a non-empty string command now return BLOCK.

### 3. Interceptor execution flag corrected

`executed` now represents actual execution, not merely an ALLOW decision.

### 4. Interceptor defense-in-depth added

Even if a bad policy engine accidentally returns ALLOW for an unsupported tool, the interceptor blocks at the execution boundary.

### 5. Key permissions hardened

The key directory is restricted to owner access and private key creation uses restrictive permissions at creation time.

## Known MVP Limitations

These are acceptable for the current local proof, but should be addressed before production use.

1. `shell.run` still uses `shell=True`. For production, replace raw shell strings with structured argument vectors or a tightly scoped command registry.
2. Verification currently uses the local public key from `.lexecon/`. Add an explicit `--public-key` option for portable third-party verification.
3. The audit ledger is JSONL append-only by convention, not protected by OS-level immutability.
4. Policy matching is simple substring matching. Future versions should use normalized command parsing and rule precedence.
5. There is no capability-token layer yet.
6. There are no OpenAI or Anthropic adapters yet.
7. There is no remote attestation or transparency log yet.

## Bottom Line

Lexecon Core now proves the MVP primitive:

```txt
attempted action -> deterministic policy decision -> execution gate -> signed audit record -> verifiable ledger
```

This is strong enough for a local technical demo. The next serious hardening step is to replace raw shell execution with a structured command registry and make verification portable through an explicit public-key path.
