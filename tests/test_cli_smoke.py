"""CLI smoke tests — invoke lexecon entrypoints as subprocesses."""
import subprocess
import sys
from pathlib import Path


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    # Use sys.executable so smoke tests always run under the same interpreter as pytest.
    return subprocess.run(
        [sys.executable, "-m", "lexecon.cli"] + args,
        capture_output=True,
        text=True,
        cwd=cwd,
    )


def test_smoke_init_keys(tmp_path):
    """lexecon init-keys must exit 0 and create key files."""
    result = _run(["init-keys"], cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / ".lexecon" / "private_key.pem").exists()
    assert (tmp_path / ".lexecon" / "public_key.pem").exists()


def test_smoke_demo(tmp_path):
    """lexecon demo must exit 0 and report BLOCK with no execution."""
    result = _run(["demo"], cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "Decision: BLOCK" in result.stdout
    assert "Executed: false" in result.stdout
    assert "Ledger verification: valid" in result.stdout


def test_smoke_demo_creates_ledger(tmp_path):
    """lexecon demo must write a ledger file."""
    _run(["demo"], cwd=tmp_path)
    assert (tmp_path / ".audit" / "ledger.jsonl").exists()


def test_smoke_verify_valid(tmp_path):
    """lexecon verify must report VALID on a ledger written by demo."""
    _run(["demo"], cwd=tmp_path)
    ledger_path = str(tmp_path / ".audit" / "ledger.jsonl")
    result = _run(["verify", ledger_path], cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "Status: VALID" in result.stdout


def test_smoke_verify_with_explicit_public_key(tmp_path):
    """lexecon verify --public-key must accept an explicit key path and report VALID."""
    _run(["demo"], cwd=tmp_path)
    ledger_path = str(tmp_path / ".audit" / "ledger.jsonl")
    pub_key_path = str(tmp_path / ".lexecon" / "public_key.pem")
    result = _run(["verify", ledger_path, "--public-key", pub_key_path], cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "Status: VALID" in result.stdout


def test_smoke_verify_missing_ledger(tmp_path):
    """lexecon verify on a nonexistent ledger must report INVALID."""
    missing = str(tmp_path / "nonexistent.jsonl")
    result = _run(["verify", missing], cwd=tmp_path)
    assert "Status: INVALID" in result.stdout or result.returncode != 0
