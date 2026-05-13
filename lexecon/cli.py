"""CLI for Lexecon Core."""
from pathlib import Path
from typing import Optional

import typer

from lexecon.audit.ledger import Ledger
from lexecon.audit.signer import Signer
from lexecon.audit.verifier import Verifier
from lexecon.enforcement.interceptor import Interceptor
from lexecon.enforcement.policy_engine import PolicyEngine

app = typer.Typer(name="lexecon")


@app.command()
def init_keys():
    """Initialize local Ed25519 keypair."""
    signer = Signer()
    _ = signer.private_key
    _ = signer.public_key
    typer.echo("Keys initialized.")
    typer.echo("Private key: .lexecon/private_key.pem")
    typer.echo("Public key:  .lexecon/public_key.pem")


@app.command()
def demo():
    """
    Run the demo:
    1. Initialize keys if missing.
    2. Attempt a destructive shell command through the interceptor.
    3. Print results.
    """
    # Initialize keys if missing
    signer = Signer()
    _ = signer.private_key

    # Initialize ledger
    ledger = Ledger(signer=signer)

    # Initialize policy and interceptor
    policy_engine = PolicyEngine()
    interceptor = Interceptor(policy_engine, ledger)

    # Attempt destructive command (structured args — no shell=True)
    tool_call = {
        "tool": "shell.run",
        "args": {"executable": "rm", "args": ["-rf", "./important_data"]},
    }

    result = interceptor.intercept(tool_call)

    # Verify ledger
    verifier = Verifier(signer=signer)
    verification = verifier.verify_ledger(Path(".audit/ledger.jsonl"))

    # Print output
    typer.echo(f"Attempted tool call: {tool_call['tool']}")
    typer.echo(f"Decision: {result['decision']}")
    typer.echo(f"Reason: {result['reason']}")
    typer.echo(f"Executed: {str(result['executed']).lower()}")
    typer.echo("Audit record written: true")
    typer.echo(f"Ledger verification: {'valid' if verification['valid'] else 'invalid'}")


@app.command()
def verify(
    path: str,
    public_key: Optional[Path] = typer.Option(
        None,
        "--public-key",
        help="Path to Ed25519 public key PEM for third-party verification. Defaults to .lexecon/public_key.pem.",
    ),
):
    """Verify an audit ledger at the given path."""
    ledger_path = Path(path)
    signer = Signer(public_key_path=public_key)
    verifier = Verifier(signer=signer)
    result = verifier.verify_ledger(ledger_path)

    typer.echo(f"Ledger: {ledger_path}")
    typer.echo(f"Records: {result['record_count']}")
    if result["valid"]:
        typer.echo("Status: VALID")
    else:
        typer.echo("Status: INVALID")
        if result["errors"]:
            typer.echo("Errors:")
            for error in result["errors"]:
                typer.echo(f"  - {error}")


if __name__ == "__main__":
    app()
