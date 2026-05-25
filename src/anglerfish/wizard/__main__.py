"""Typer entry point for the first-boot wizard.

Run interactively as ``anglerfish-wizard`` (the entry point) or
``python -m anglerfish.wizard``. Two modes:

* **first-boot** (default) — prompts from scratch.
* ``--reconfigure`` — loads the previously-saved
  ``/etc/anglerfish/wizard.json`` and pre-fills every prompt with the
  current value. Operators using this mode should restart the bridge
  + dashboard afterwards because the shared secret rotates.

System path overrides (``--systemd-network-dir`` etc.) exist for tests
and unusual deployments. Production deployments accept the defaults.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.prompt import Confirm, Prompt

from anglerfish.cli.banner import write_banner
from anglerfish.wizard.persistence import DEFAULT_ANSWERS_PATH, load_answers
from anglerfish.wizard.wizard import (
    TermsDeclinedError,
    WizardPaths,
    prompt_for_answers,
    run_wizard,
)

__all__ = ["app"]


app = typer.Typer(
    name="anglerfish-wizard",
    help="Anglerfish AI first-boot configuration wizard.",
    add_completion=False,
    no_args_is_help=False,
)


@app.command()
def run(
    env_path: Annotated[
        Path,
        typer.Option(
            "--env",
            help="Path to write the generated .env file.",
        ),
    ] = Path("/etc/anglerfish/anglerfish.env"),
    no_banner: Annotated[
        bool,
        typer.Option("--no-banner", help="Skip the ASCII banner."),
    ] = False,
    reconfigure: Annotated[
        bool,
        typer.Option(
            "--reconfigure",
            help=(
                "Load the previously-saved answers from "
                "/etc/anglerfish/wizard.json and use them as prompt defaults."
            ),
        ),
    ] = False,
    skip_preflight: Annotated[
        bool,
        typer.Option(
            "--skip-preflight",
            help="Skip reachability checks against Ollama and the alert webhook.",
        ),
    ] = False,
    systemd_network_dir: Annotated[
        Path,
        typer.Option(
            "--systemd-network-dir",
            help="Directory to write systemd-networkd .network files to.",
        ),
    ] = Path("/etc/systemd/network"),
    hostname_path: Annotated[
        Path,
        typer.Option("--hostname-path", help="Path of /etc/hostname."),
    ] = Path("/etc/hostname"),
    hosts_path: Annotated[
        Path,
        typer.Option("--hosts-path", help="Path of /etc/hosts."),
    ] = Path("/etc/hosts"),
    ops_home: Annotated[
        Path,
        typer.Option(
            "--ops-home",
            help="Home directory of the operator account (authorized_keys destination).",
        ),
    ] = Path("/home/anglerfish-ops"),
) -> None:
    """Run the first-boot wizard interactively."""
    console = Console()
    if not no_banner:
        write_banner(sys.stdout)

    def _prompt(label: str, default: str | None) -> str:
        if default is None:
            return Prompt.ask(label)
        return Prompt.ask(label, default=default)

    def _confirm(label: str, default: bool) -> bool:
        return Confirm.ask(label, default=default)

    defaults_path = DEFAULT_ANSWERS_PATH
    defaults = None
    if reconfigure:
        try:
            defaults = load_answers(defaults_path)
        except ValueError as exc:
            console.print(f"[red]Could not read {defaults_path}: {exc}[/red]")
            raise typer.Exit(code=1) from exc
        if defaults is None:
            console.print(
                f"[yellow]No prior answers at {defaults_path};[/yellow] starting from scratch.",
            )

    paths = WizardPaths(
        env_path,
        systemd_network_dir=systemd_network_dir,
        hostname_path=hostname_path,
        hosts_path=hosts_path,
        ops_home=ops_home,
    )

    try:
        answers = prompt_for_answers(
            prompt=_prompt,
            confirm=_confirm,
            output=console.print,
            defaults=defaults,
        )
        result = run_wizard(
            answers,
            env_path=env_path,
            paths=paths,
            run_preflight=not skip_preflight,
        )
    except TermsDeclinedError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    except (ValueError, OSError) as exc:
        console.print(f"[red]wizard failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    console.print(f"[green]Wrote configuration to[/green] {result.env_path}")
    console.print(f"  nftables:        {result.nftables_path}")
    console.print(f"  bait network:    {result.bait_network_path}")
    console.print(f"  service network: {result.service_network_path}")
    console.print(f"  hostname:        {result.hostname_path}")
    if result.authorized_keys_path is not None:
        console.print(f"  ops authorized_keys: {result.authorized_keys_path}")
    console.print(f"  saved answers:   {result.answers_path}")
    if result.dashboard_session_secret_generated:
        console.print("Generated new dashboard session secret.")
    if result.credentials_encryption_key_generated:
        console.print("Generated new credentials encryption key.")
    if result.bridge_shared_secret_generated:
        console.print("Generated new bridge shared secret.")
    for line in result.preflight_results:
        console.print(f"  preflight: {line}")
    if reconfigure:
        console.print(
            "[yellow]Note:[/yellow] secrets were regenerated. "
            "Restart anglerfish-bridge and anglerfish-dashboard "
            "to pick up the new values.",
        )


if __name__ == "__main__":  # pragma: no cover
    app()
