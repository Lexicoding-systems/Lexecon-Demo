"""Adapter: converts Anthropic tool_use blocks to Lexecon tool_call format.

Anthropic tool_use block (from a Claude API response):
    {
        "type": "tool_use",
        "id": "toolu_...",
        "name": "bash",
        "input": {"command": "rm -rf ./data"}
    }

Lexecon tool_call format:
    {
        "tool": "shell.run",
        "args": {"executable": "rm", "args": ["-rf", "./data"]}
    }

Tool names that map to shell.run: bash, shell, run_command, execute.
Any other tool name is forwarded as-is with input passed through as args.
"""
import shlex
from typing import Any

_SHELL_TOOL_NAMES = {"bash", "shell", "run_command", "execute"}


def from_anthropic_tool_use(tool_use_block: dict[str, Any]) -> dict[str, Any]:
    """Convert an Anthropic tool_use block to a Lexecon tool_call dict.

    Raises ValueError if tool_use_block is not a dict.
    """
    if not isinstance(tool_use_block, dict):
        raise ValueError("tool_use_block must be a dict")

    name = tool_use_block.get("name", "")
    input_ = tool_use_block.get("input") or {}

    if name in _SHELL_TOOL_NAMES:
        raw_command = input_.get("command", "")
        try:
            parts = shlex.split(raw_command)
        except ValueError:
            parts = raw_command.split()

        if not parts:
            return {
                "tool": "shell.run",
                "args": {"executable": "", "args": []},
            }
        return {
            "tool": "shell.run",
            "args": {"executable": parts[0], "args": parts[1:]},
        }

    # Non-shell tools: forward name and input unchanged.
    return {"tool": name, "args": input_}
