#!/usr/bin/env python3
"""
Demo: Block an unlisted executable through Lexecon.

'rm' is not in the default allowed_executables allowlist, so the policy
engine blocks it at the allowlist check before any pattern rules are
evaluated. To see destructive-pattern enforcement in action, allowlist 'rm'
in a custom policy and pass {"executable": "rm", "args": ["-rf", "..."]} —
the block_destructive_shell rule will then fire.
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

    # Attempt a destructive command (structured args — no shell=True)
    tool_call = {
        "tool": "shell.run",
        "args": {"executable": "rm", "args": ["-rf", "./important_data"]},
    }

    result = interceptor.intercept(tool_call)

    print(f"Decision: {result['decision']}")
    print(f"Reason: {result['reason']}")
    print(f"Executed: {result['executed']}")


if __name__ == "__main__":
    main()
