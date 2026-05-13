"""Shell tool wrapper for Lexecon."""
import subprocess
from typing import Any


def shell_run(executable: str, args: list[str], timeout: int = 10) -> dict[str, Any]:
    """
    Execute a structured command via subprocess without shell interpretation.
    Does NOT call policy engine — caller (Interceptor) gates execution.
    """
    result = subprocess.run(
        [executable] + args,
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }
