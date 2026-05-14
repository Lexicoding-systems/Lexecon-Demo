"""CLI for Lexecon Core."""
from pathlib import Path
from typing import Optional

import typer

from lexecon.adapters.anthropic_adapter import from_anthropic_tool_use
from lexecon.audit.ledger import Ledger
from lexecon.audit.signer import Signer
from lexecon.audit.verifier import Verifier
from lexecon.enforcement.interceptor import Interceptor
from lexecon.enforcement.policy_engine import PolicyEngine

app = typer.Typer(name="lexecon")

_DEMO_POLICY_PATH = Path(__file__).parent / "policies" / "demo_policy.yaml"


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
def demo(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print step-by-step enforcement narrative."),
):
    """
    Run the demo:
    1. Simulate an Anthropic tool_use block for a destructive command.
    2. Convert it via the Anthropic adapter.
    3. Intercept via policy + audit.
    4. Print results (with --verbose for step-by-step narration).
    """
    # Simulate what Claude would emit as a tool_use response
    anthropic_tool_use = {
        "type": "tool_use",
        "id": "toolu_demo_001",
        "name": "bash",
        "input": {"command": "rm -rf ./important_data"},
    }

    if verbose:
        typer.echo("[LEXECON] ── Demo: Anthropic tool_use interceptor ──────────────────")
        typer.echo(f"[LEXECON] AI agent emitted tool_use: {anthropic_tool_use['name']!r}")
        typer.echo(f"[LEXECON]   command: {anthropic_tool_use['input']['command']!r}")

    # Convert Anthropic tool_use → Lexecon tool_call
    tool_call = from_anthropic_tool_use(anthropic_tool_use)

    if verbose:
        typer.echo("[LEXECON] Adapter converted to Lexecon tool_call:")
        typer.echo(f"[LEXECON]   tool={tool_call['tool']!r}  executable={tool_call['args']['executable']!r}  args={tool_call['args']['args']}")

    # Initialize keys, ledger, and interceptor with the demo policy
    signer = Signer()
    _ = signer.private_key

    ledger = Ledger(signer=signer)
    policy_engine = PolicyEngine(policy_path=_DEMO_POLICY_PATH)
    interceptor = Interceptor(policy_engine, ledger)

    if verbose:
        typer.echo("[LEXECON] Intercepting before execution...")
        typer.echo("[LEXECON] Policy engine evaluating...")

    result = interceptor.intercept(tool_call)

    if verbose:
        if result["decision"] == "BLOCK":
            typer.echo(f"[LEXECON] Rule matched → {result.get('audit_record_id', '')[:12]}... policy_id in audit record")
            typer.echo(f"[LEXECON] BLOCKED — command did NOT execute")
        else:
            typer.echo(f"[LEXECON] Decision: {result['decision']} — command executed")
        typer.echo(f"[LEXECON] Reason: {result['reason']}")
        typer.echo(f"[LEXECON] Audit record written: {result['audit_record_id']}")

    # Verify ledger
    verifier = Verifier(signer=signer)
    verification = verifier.verify_ledger(Path(".audit/ledger.jsonl"))

    if verbose:
        count = verification["record_count"]
        status = "valid" if verification["valid"] else "INVALID"
        typer.echo(f"[LEXECON] Chain verified: {count} record(s), all signatures {status}")
        typer.echo("[LEXECON] ── Try `lexecon verify .audit/ledger.jsonl` after editing the ledger ──")
    else:
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
