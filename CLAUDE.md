# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Lexecon Core is a **runtime enforcement layer for AI agent tool calls**. It intercepts a proposed tool call, evaluates it against a deterministic YAML policy, writes a cryptographically verifiable (Ed25519-signed, SHA-256 hash-chained) audit record, and gates execution — blocked calls never run. The MVP supports only the `shell.run` tool.

## Commands

```bash
# Install (includes dev dependencies)
pip install -e ".[dev]"

# Run all tests
pytest

# Run a single test file
pytest tests/test_demo_flow.py

# Run a single test
pytest tests/test_demo_flow.py::test_demo_flow_blocks_destructive_command

# CLI workflow
lexecon init-keys               # generate Ed25519 keypair into .lexecon/
lexecon demo                    # intercept a destructive command end-to-end
lexecon verify .audit/ledger.jsonl  # verify ledger integrity
```

CI runs `pytest` against Python 3.11 and 3.12 on every push/PR.

## Architecture and Data Flow

```
Proposed tool call dict
  → Interceptor.intercept()
      → PolicyEngine.evaluate()        # deterministic YAML match, never LLM
          → Decision (ALLOW/BLOCK/ESCALATE)
      → Ledger.write_record()          # always runs, even for BLOCK
          → AuditRecord (SHA-256 hash of record, Ed25519 signature, chain link)
          → appended to .audit/ledger.jsonl
      → if ALLOW and tool == "shell.run": shell_run(command)
      → return structured dict
```

The three layers are strictly ordered: **policy → audit → execution**. No tool ever runs before a policy decision, and no blocked call ever executes.

### Module Responsibilities

| Module | Responsibility |
|--------|---------------|
| `enforcement/decision.py` | `DecisionType` enum (ALLOW/BLOCK/ESCALATE) and `Decision` dataclass |
| `enforcement/policy_engine.py` | Load YAML rules; substring-match patterns against `shell.run` command arg; fail-closed on exceptions |
| `enforcement/interceptor.py` | The enforcement boundary; the only place execution is ever gated |
| `tools/shell.py` | Thin `subprocess` wrapper — zero policy logic, called only after ALLOW |
| `audit/record.py` | `AuditRecord` dataclass; `hash_tool_args` (SHA-256 of canonical JSON); `compute_record_hash` (excludes `record_hash` and `signature` fields) |
| `audit/ledger.py` | Append-only JSONL at `.audit/ledger.jsonl`; maintains hash chain via `previous_hash`; calls `Signer` |
| `audit/signer.py` | Ed25519 key gen/load from `.lexecon/`; sign returns base64 string; `verify` is exception-safe (returns bool) |
| `audit/verifier.py` | Offline verifier: recomputes hashes, checks chain, verifies signatures |
| `policies/default_policy.yaml` | Single rule `block_destructive_shell` blocking `rm -rf`, `sudo rm`, `mkfs`, `diskutil erase` |
| `cli.py` | Typer app wiring `init-keys`, `demo`, `verify` |

## Key Invariants

1. **Fail-closed everywhere**: any exception in `PolicyEngine.evaluate()` or `Interceptor.intercept()` produces `BLOCK`, never `ALLOW`.
2. **Audit records never store raw tool args** — only the SHA-256 hash (`tool_args_hash`).
3. **Hash chain**: first record has `previous_hash == "GENESIS"`; each subsequent record's `previous_hash` must equal the previous record's `record_hash`. The verifier independently recomputes hashes to detect tampering.
4. **Defense-in-depth in interceptor**: even if policy returns `ALLOW` for an unknown tool name, the interceptor explicitly blocks any tool that is not `shell.run`.
5. **Only one supported tool**: `PolicyEngine.SUPPORTED_TOOLS = {"shell.run"}`. Adding a new tool requires updating this set and adding interceptor dispatch.
6. **Structured args, no shell injection**: `shell.run` tool calls use `{"executable": str, "args": list[str]}` — never a raw command string. `shell_run()` uses `subprocess.run([executable] + args, shell=False)`. The policy engine rejects any executable not listed in `allowed_executables` (policy YAML) before reaching pattern checks.
7. **No bypass enforcement at the tools layer**: `lexecon/tools/shell.py` has no policy or audit logic. Any code that imports and calls `shell_run()` directly — or spawns a subprocess by any other means — silently bypasses all Lexecon guarantees. The integrator is responsible for routing every tool call through `Interceptor.intercept()`.

## Policy YAML Format

```yaml
allowed_executables:        # positive allowlist — unlisted executables are BLOCKed
  - ls
  - echo

rules:
  - id: block_destructive_shell   # unique rule ID surfaced in audit records
    tool: shell.run               # exact match against tool_call["tool"]
    action: BLOCK                 # BLOCK or ESCALATE
    patterns:                     # substring match against "<executable> <args...>"
      - "rm -rf"
    reason: "Destructive shell command detected."
```

Custom policies can be passed via `PolicyEngine(policy_path=Path("custom.yaml"))`.

## Tool Call Schema

```python
# shell.run tool call — structured args, no shell string
tool_call = {
    "tool": "shell.run",
    "args": {
        "executable": "echo",     # must be in policy allowed_executables
        "args": ["hello", "world"],  # list of string arguments
    },
}
```

## Test Conventions

- All tests use `tmp_path` for file isolation — never write to `.audit/` or `.lexecon/` from tests.
- Stub actual shell execution with `monkeypatch.setattr("lexecon.tools.shell.shell_run", ...)` — the interceptor imports `shell_run` lazily inside the `if decision.allowed` branch, so patching the module-level name works. Stub signature: `def fake(executable, args, timeout=10)`.
- The most critical test is `test_interceptor_never_executes_blocked_tool` in `tests/test_interceptor.py` — it asserts the stub was never called when policy returns BLOCK.
- `tests/test_demo_flow.py` contains the end-to-end integration tests including multi-record chain verification.

## Model Hygiene

All contributions to this repository must be made by a single consistent AI model (or human). Do **not** mix model outputs. Mixing models introduces inconsistent style, redundant abstractions, and hidden assumptions that accumulate as code debt. If you are continuing work started by another model, audit the existing code before adding to it — do not layer on top of conflicting patterns.

## Local State (Gitignored)

- `.lexecon/` — Ed25519 key files (`private_key.pem` mode 0600, `public_key.pem`)
- `.audit/` — `ledger.jsonl` JSONL audit log

Both directories are created automatically on first use; running `lexecon init-keys` pre-creates them explicitly.
