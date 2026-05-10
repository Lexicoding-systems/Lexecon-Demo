# Lexecon Core

Runtime policy enforcement and cryptographic audit trails for AI agent tool calls.

Lexecon is an execution control layer for AI agents. It sits between an agent and its tools, intercepts attempted actions before they execute, checks them against policy, and writes a verifiable audit record of every decision.

The core idea is simple:

> If an AI agent can act, its actions need to be governed before execution.

## What Lexecon Does

Lexecon provides a minimal enforcement runtime for agent tool calls.

It can:

1. Receive an attempted tool call.
2. Evaluate the call against a declarative policy.
3. Return `ALLOW`, `BLOCK`, or `ESCALATE`.
4. Prevent blocked tools from executing.
5. Write an audit record for every decision.
6. Hash-chain audit records.
7. Sign records for later verification.
8. Let a verifier confirm the decision trail has not been tampered with.

## Core Demo

The initial demo shows Lexecon blocking a destructive shell command before it executes.

Flow:

```txt
1. User asks an agent to clean up files.
2. Agent attempts: shell.run("rm -rf ./important_data")
3. Lexecon intercepts the tool call.
4. Policy detects a destructive command.
5. Lexecon returns BLOCK.
6. The shell tool never executes.
7. An audit record is written.
8. The record is hash-chained and signed.
9. User runs the verifier.
10. Verifier confirms the audit trail is valid.
