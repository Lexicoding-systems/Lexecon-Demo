"""Deterministic policy engine for tool call evaluation."""
from pathlib import Path
from typing import Any

import yaml

from .decision import Decision, DecisionType


DEFAULT_POLICY_PATH = Path(__file__).parent.parent / "policies" / "default_policy.yaml"
SUPPORTED_TOOLS = {"shell.run"}


class PolicyEngine:
    """Deterministic policy evaluation. This path never uses an LLM."""

    def __init__(self, policy_path: Path | None = None):
        self.policy_path = policy_path or DEFAULT_POLICY_PATH
        policy_data = self._load_policy()
        self.rules: list[dict[str, Any]] = policy_data["rules"]
        self.allowed_executables: set[str] = set(policy_data["allowed_executables"])

    def _load_policy(self) -> dict[str, Any]:
        with open(self.policy_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        rules = data.get("rules", [])
        if not isinstance(rules, list):
            raise ValueError("Policy file must contain a list under 'rules'.")
        allowed_executables = data.get("allowed_executables", [])
        if not isinstance(allowed_executables, list):
            raise ValueError("Policy file must contain a list under 'allowed_executables'.")
        return {"rules": rules, "allowed_executables": allowed_executables}

    def evaluate(self, tool_call: dict[str, Any]) -> Decision:
        """
        Evaluate a tool call against loaded policy rules.

        Security posture:
        - Unknown tools are blocked.
        - Malformed input is blocked.
        - Executables not on the allowlist are blocked.
        - Matching BLOCK rules block execution.
        - No blocking match for a supported, allowlisted tool returns ALLOW.
        - Any exception returns BLOCK.
        """
        try:
            if not isinstance(tool_call, dict):
                return Decision(DecisionType.BLOCK, "Malformed tool call: not a dict.", "error")

            tool_name = tool_call.get("tool")
            if not isinstance(tool_name, str) or not tool_name:
                return Decision(DecisionType.BLOCK, "Malformed tool call: missing tool name.", "error")

            if tool_name not in SUPPORTED_TOOLS:
                return Decision(DecisionType.BLOCK, f"Unsupported tool for MVP: {tool_name}", "unsupported_tool")

            args = tool_call.get("args")
            if not isinstance(args, dict):
                return Decision(DecisionType.BLOCK, "Malformed tool args: args must be a dict.", "error")

            executable = args.get("executable")
            if not isinstance(executable, str) or not executable.strip():
                return Decision(
                    DecisionType.BLOCK,
                    "Malformed shell.run args: executable must be a non-empty string.",
                    "error",
                )

            cmd_args = args.get("args", [])
            if not isinstance(cmd_args, list):
                return Decision(
                    DecisionType.BLOCK,
                    "Malformed shell.run args: args must be a list.",
                    "error",
                )
            if not all(isinstance(a, str) for a in cmd_args):
                return Decision(
                    DecisionType.BLOCK,
                    "Malformed shell.run args: every element of args must be a string.",
                    "error",
                )

            # Allowlist check: only explicitly permitted executables may run.
            if executable not in self.allowed_executables:
                return Decision(
                    DecisionType.BLOCK,
                    f"Executable not in allowlist: {executable}",
                    "not_allowlisted",
                )

            # Pattern-based block rules (checked against full arg string for compatibility).
            arg_string = " ".join([executable] + cmd_args)
            for rule in self.rules:
                if tool_name != rule.get("tool"):
                    continue

                action = str(rule.get("action", "ALLOW")).upper()
                patterns = rule.get("patterns", [])
                if not isinstance(patterns, list):
                    return Decision(DecisionType.BLOCK, "Malformed policy rule: patterns must be a list.", "error")

                for pattern in patterns:
                    if isinstance(pattern, str) and pattern in arg_string:
                        decision_type = DecisionType.BLOCK if action == "BLOCK" else DecisionType.ESCALATE
                        return Decision(
                            decision_type,
                            rule.get("reason", "Policy pattern matched."),
                            rule.get("id", "unknown"),
                        )

            return Decision(DecisionType.ALLOW, "No blocking rule matched.", "default")

        except Exception as exc:
            return Decision(DecisionType.BLOCK, f"Policy evaluation error: {exc}", "error")
