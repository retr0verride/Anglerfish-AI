"""``anglerfish`` command-line entrypoint.

The honeypot itself runs under systemd; this CLI is the operator's
tool for inspecting configuration, rendering the banner, and serving
the bridge HTTP API.
"""

from __future__ import annotations

import sys
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.panel import Panel

from anglerfish import __version__
from anglerfish.audit import AuditLog
from anglerfish.cli.banner import write_banner
from anglerfish.config import load_settings

__all__ = ["app"]


app = typer.Typer(
    name="anglerfish",
    help="Anglerfish AI — AI-powered SSH honeypot.",
    add_completion=False,
    no_args_is_help=True,
)
config_app = typer.Typer(
    name="config",
    help="Inspect Anglerfish AI configuration.",
    no_args_is_help=True,
)
bridge_app = typer.Typer(
    name="bridge",
    help="Bridge service commands.",
    no_args_is_help=True,
)
credentials_app = typer.Typer(
    name="credentials",
    help="Credential intelligence database operations.",
    no_args_is_help=True,
)
geo_app = typer.Typer(
    name="geo",
    help="MaxMind GeoLite2 database management.",
    no_args_is_help=True,
)
lure_app = typer.Typer(
    name="lure",
    help="Native SSH lure (Cowrie replacement) commands.",
    no_args_is_help=True,
)
app.add_typer(config_app)
app.add_typer(bridge_app)
app.add_typer(credentials_app)
app.add_typer(geo_app)
app.add_typer(lure_app)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"anglerfish-ai {__version__}")
        raise typer.Exit


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    del version


@app.command()
def banner(
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable ANSI colour output."),
    ] = False,
) -> None:
    """Print the Anglerfish ASCII banner."""
    write_banner(sys.stdout, color=not no_color)


@config_app.command("show")
def config_show() -> None:
    """Load, validate, and print the configuration (secrets masked)."""
    console = Console()
    try:
        settings = load_settings()
    except ValidationError as exc:
        console.print(Panel(str(exc), title="[red]Configuration error[/red]"))
        raise typer.Exit(code=2) from exc
    console.print_json(data=settings.model_dump(mode="json"))


@bridge_app.command("serve")
def bridge_serve(
    host: Annotated[
        str,
        typer.Option("--host", help="Interface to bind the bridge HTTP server to."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", help="TCP port for the bridge HTTP server."),
    ] = 8421,
) -> None:  # pragma: no cover - exercised in integration
    """Run the bridge HTTP API for Cowrie to consume.

    This boots a Uvicorn server hosting :func:`anglerfish.bridge.create_bridge_app`.
    Use only with a configured ``.env`` (see ``anglerfish config show``).
    """
    import asyncio

    import uvicorn

    from anglerfish.audit import AuditLog
    from anglerfish.bridge import AIBridgeService, OllamaClient, create_bridge_app
    from anglerfish.bridge.defense import ModelIntegrityError, verify_all_roles

    try:
        settings = load_settings()
    except ValidationError as exc:
        Console().print(Panel(str(exc), title="[red]Configuration error[/red]"))
        raise typer.Exit(code=2) from exc

    # Shared audit log: defense fires (per-request) AND model integrity
    # results (startup) both write to the same JSONL append-only log.
    audit_log = AuditLog(settings.audit.log_path)
    ai_client = OllamaClient(settings.ollama)

    # Pre-uvicorn integrity check: walk every configured LLM role
    # (Stage 5 ships fast + deep). Runs BEFORE uvicorn.run() so any
    # failure surfaces as a structured Console panel + clean
    # typer.Exit(2), not a raw traceback in journalctl. The lifespan
    # path stays available for tests of create_bridge_app in isolation
    # (we pass integrity=None below so it doesn't double-check).
    # Per-role budget: 10s times number of roles (two today).
    roles_verified = 2
    timeout_s = 10.0 * roles_verified
    try:
        asyncio.run(
            asyncio.wait_for(
                verify_all_roles(
                    defense_config=settings.defense,
                    ollama_config=settings.ollama,
                    audit_log=audit_log,
                ),
                timeout=timeout_s,
            ),
        )
    except ModelIntegrityError as exc:
        Console().print(
            Panel(str(exc), title="[red]Model integrity check failed[/red]"),
        )
        raise typer.Exit(code=2) from exc
    except TimeoutError as exc:
        Console().print(
            Panel(
                f"Model integrity check timed out after {timeout_s}s. Check that "
                f"ollama_manifest_dir ({settings.defense.ollama_manifest_dir}) "
                "is reachable.",
                title="[red]Model integrity check timed out[/red]",
            ),
        )
        raise typer.Exit(code=2) from exc

    service = AIBridgeService(settings, client=ai_client, audit_log=audit_log)
    # integrity=None: we already verified above; passing the instance
    # would cause a redundant second verify() in the lifespan.
    application = create_bridge_app(service, integrity=None)
    uvicorn.run(application, host=host, port=port, log_level=settings.log_level.value.lower())


@credentials_app.command("rotate-key")
def credentials_rotate_key(
    new_key: Annotated[
        str,
        typer.Option(
            "--new-key",
            help=("Base64-encoded 32-byte AES-GCM key. Generate one with: openssl rand -base64 32"),
        ),
    ],
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip the confirmation prompt."),
    ] = False,
) -> None:
    """Rotate the credentials encryption key.

    Stops the world (you must stop the bridge + dashboard first),
    re-encrypts every credential record under the new key, and leaves
    the previous DB as ``<path>.bak``.
    """
    console = Console()
    try:
        settings = load_settings()
    except ValidationError as exc:
        console.print(Panel(str(exc), title="[red]Configuration error[/red]"))
        raise typer.Exit(code=2) from exc

    from anglerfish.credentials import CredentialCipher, RotationError, rotate_key

    db_path = settings.credentials.database_path
    if not db_path.exists():
        console.print(f"[red]No credentials database at {db_path}[/red]")
        raise typer.Exit(code=1)

    console.print(f"Credentials DB: {db_path}")
    console.print(
        "[yellow]This will rewrite every credential row under a new key.[/yellow]",
    )
    console.print(
        "[yellow]Stop anglerfish-bridge and anglerfish-dashboard before continuing.[/yellow]",
    )
    if not yes:
        confirmed = typer.confirm("Proceed with rotation?", default=False)
        if not confirmed:
            console.print("Aborted.")
            raise typer.Exit(code=1)

    try:
        old_cipher = CredentialCipher(
            settings.credentials.encryption_key.get_secret_value(),
        )
        new_cipher = CredentialCipher(new_key)
    except ValueError as exc:
        console.print(f"[red]Invalid encryption key: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    try:
        result = rotate_key(
            db_path=db_path,
            old_cipher=old_cipher,
            new_cipher=new_cipher,
        )
    except RotationError as exc:
        console.print(f"[red]Rotation failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    console.print(f"[green]Rotated {result.rows_rotated} records.[/green]")
    if result.rows_skipped:
        console.print(
            f"[yellow]Skipped {result.rows_skipped} undecryptable records.[/yellow]",
        )
    console.print(f"Previous DB preserved at {result.backup_path}")
    console.print(
        "Update ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY in "
        "/etc/anglerfish/anglerfish.env to the new key, then restart "
        "anglerfish-bridge and anglerfish-dashboard.",
    )
    AuditLog(settings.audit.log_path).record(
        "credentials.key_rotated",
        rows_rotated=result.rows_rotated,
        rows_skipped=result.rows_skipped,
        backup_path=str(result.backup_path),
    )


@geo_app.command("update")
def geo_update() -> None:
    """Download fresh MaxMind GeoLite2 databases.

    Runs at first boot (via the ``anglerfish-geo-update`` systemd unit)
    and weekly thereafter. No-op when no MaxMind licence key is
    configured.
    """
    console = Console()
    try:
        settings = load_settings()
    except ValidationError as exc:
        console.print(Panel(str(exc), title="[red]Configuration error[/red]"))
        raise typer.Exit(code=2) from exc

    from anglerfish.geo import FetchError, fetch_geolite_databases

    try:
        results = fetch_geolite_databases(settings.geo)
    except FetchError as exc:
        console.print(f"[red]Geo update failed: {exc}[/red]")
        AuditLog(settings.audit.log_path).record("geo.update_failed", error=str(exc))
        raise typer.Exit(code=1) from exc

    if not results:
        console.print("MaxMind licence key not configured — skipping update.")
        return

    for result in results:
        console.print(
            f"[green]{result.edition}[/green] → {result.destination} "
            f"({result.bytes_written:,} bytes, sha256={result.sha256[:12]}…)",
        )
    AuditLog(settings.audit.log_path).record(
        "geo.update_succeeded",
        editions=[r.edition for r in results],
    )


@lure_app.command("serve")
def lure_serve() -> None:  # pragma: no cover - exercised in integration
    """Run the native SSH lure listener.

    Blocks on the asyncio loop until SIGTERM or SIGINT is received.
    Exits 2 on bait-NIC validation failure, 0 on graceful shutdown.
    """
    import asyncio
    import logging

    from anglerfish.lure.runner import BaitNicError, run_lure

    console = Console()
    try:
        settings = load_settings()
    except ValidationError as exc:
        console.print(Panel(str(exc), title="[red]Configuration error[/red]"))
        raise typer.Exit(code=2) from exc

    logging.basicConfig(level=settings.log_level.value)
    try:
        asyncio.run(run_lure(settings))
    except BaitNicError as exc:
        console.print(
            Panel(str(exc), title="[red]Lure bait-NIC validation failed[/red]"),
        )
        raise typer.Exit(code=2) from exc


@lure_app.command("validate-config")
def lure_validate_config() -> None:
    """Run the lure's startup checks without binding the listener.

    Loads settings, generates / verifies host keys, and runs the
    bait-NIC presence check. Exits 0 on success, non-zero with a
    diagnostic on the first failure. Safe to run on a host that
    already has the lure listener bound.
    """
    from anglerfish.lure.keys import HostKeyPermissionError, ensure_host_keys, load_host_keys
    from anglerfish.lure.server import BaitNicError, validate_bait_nic

    console = Console()
    try:
        settings = load_settings()
    except ValidationError as exc:
        console.print(Panel(str(exc), title="[red]Configuration error[/red]"))
        raise typer.Exit(code=2) from exc

    if not settings.lure.enabled:
        console.print(
            "[yellow]lure.enabled is False; the listener would not bind. "
            "Skipping bait-NIC check.[/yellow]",
        )
        raise typer.Exit(code=0)

    try:
        ensure_host_keys(settings.lure.host_key_dir)
        load_host_keys(settings.lure.host_key_dir)
    except (HostKeyPermissionError, OSError) as exc:
        console.print(
            Panel(str(exc), title="[red]Lure host-key check failed[/red]"),
        )
        raise typer.Exit(code=2) from exc

    try:
        validate_bait_nic(str(settings.lure.listen_host))
    except BaitNicError as exc:
        console.print(
            Panel(str(exc), title="[red]Lure bait-NIC validation failed[/red]"),
        )
        raise typer.Exit(code=2) from exc

    console.print(
        f"[green]lure config OK[/green] - listener would bind to "
        f"{settings.lure.listen_host}:{settings.lure.listen_port}",
    )


if __name__ == "__main__":  # pragma: no cover
    app()
