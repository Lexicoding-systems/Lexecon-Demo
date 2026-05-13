"""Tool call interceptor with policy enforcement."""
from typing import Any, TYPE_CHECKING

from .decision import DecisionType
from .policy_engine import PolicyEngine

if TYPE_CHECKING:
    from ..audit.ledger import Ledger


class Interceptor:
    """Intercepts tool calls, evaluates policy, writes audit, and gates execution."""

    def __init__(self, policy_engine: PolicyEngine, ledger: "Ledger"):
        self.policy_engine = policy_engine
        self.ledger = ledger

    def intercept(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        """
        Enforce the execution boundary.

        Ordering invariant:
        policy decision -> audit write -> optional execution.
        """
        audit_record_id = ""
        try:
            decision = self.policy_engine.evaluate(tool_call)
            audit_record = self.ledger.write_record(tool_call if isinstance(tool_call, dict) else {}, decision)
            audit_record_id = audit_record.record_id

            executed = False
            tool_result = None

            if decision.allowed:
                tool_name = tool_call.get("tool", "") if isinstance(tool_call, dict) else ""
                if tool_name != "shell.run":
                    # Defense-in-depth: unsupported tools are never executed even if a policy bug ALLOWs them.
                    return {
                        "decision": DecisionType.BLOCK.value,
                        "executed": False,
                        "tool_result": None,
                        "audit_record_id": audit_record_id,
                        "reason": f"Unsupported tool reached execution boundary: {tool_name}",
                    }

                from ..tools.shell import shell_run

                tool_args = tool_call.get("args", {})
                executable = tool_args.get("executable", "")
                cmd_args = tool_args.get("args", [])
                tool_result = shell_run(executable, cmd_args)
                executed = True

            return {
                "decision": decision.decision.value,
                "executed": executed,
                "tool_result": tool_result,
                "audit_record_id": audit_record_id,
                "reason": decision.reason,
            }

        except Exception as exc:
            # Fail-closed: any error in interception prevents execution.
            # audit_record_id is preserved here if the audit write succeeded before the error.
            return {
                "decision": DecisionType.BLOCK.value,
                "executed": False,
                "tool_result": None,
                "audit_record_id": audit_record_id,
                "reason": f"Interceptor error: {exc}",
            }
