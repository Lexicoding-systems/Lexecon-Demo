"""Shell tool wrapper for Lexecon."""
import subprocess
from typing import Any


def shell_run(command: str, timeout: int = 10) -> dict[str, Any]:
    """
    Execute a shell command via subprocess.
    Does NOT call policy engine — caller (Interceptor) gates execution.
    """
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }
