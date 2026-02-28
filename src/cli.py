"""
Vigil-AI - Command-Line Interface
=================================
Entry point for the Vigil-AI autonomous Web3 security auditor.

Commands
--------
  vigil-ai                         Start interactive shell
  vigil-ai scan --path   <dir>     Scan a local file or directory
  vigil-ai scan --url    <url>     Clone a GitHub repo and scan it
  vigil-ai scan --address <addr>   Fetch a deployed contract and scan it
               --chain   <chain>   (default: ethereum)
               --api-key <key>     Optional explorer API key
"""

from __future__ import annotations

from dataclasses import dataclass
import shlex
from typing import Optional

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from inputs import ChainLoader, GitHubLoader, LocalLoader, SUPPORTED_CHAINS

app = typer.Typer(
    name="vigil-ai",
    help="Vigil-AI: The Autonomous Web3 Security Auditor",
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


def show_welcome_banner() -> None:
    banner_text = """
[bold cyan]__      __ [/bold cyan]  [bold blue]_____ [/bold blue]  [bold cyan]  ____  [/bold cyan]  [bold blue]_____ [/bold blue]  [bold cyan] _      [/bold cyan]      [bold white]   ___   [/bold white] [bold cyan] ____  [/bold cyan]
[bold cyan]\\ \\    / / [/bold cyan] [bold blue]|_   _|[/bold blue]  [bold cyan] / __ \\ [/bold cyan] [bold blue]|_   _|[/bold blue]  [bold cyan]| |     [/bold cyan]      [bold white]  / _ \\  [/bold white] [bold cyan]|_   _| [/bold cyan]
[bold cyan] \\ \\  / /  [/bold cyan]   [bold blue]| |  [/bold blue]  [bold cyan]| |  \\_|[/bold cyan]   [bold blue]| |  [/bold blue]  [bold cyan]| |     [/bold cyan]      [bold white] | | | | [/bold white]   [bold cyan]| |   [/bold cyan]
[bold cyan]  \\ \\/ /   [/bold cyan]   [bold blue]| |  [/bold blue]  [bold cyan]| | __  [/bold cyan]   [bold blue]| |  [/bold blue]  [bold cyan]| |     [/bold cyan]      [bold white] | |_| | [/bold white]   [bold cyan]| |   [/bold cyan]
[bold cyan]   \\  /    [/bold cyan]  [bold blue]_| |_ [/bold blue]  [bold cyan]| |_\\ \\ [/bold cyan]  [bold blue]_| |_ [/bold blue]  [bold cyan]| |____ [/bold cyan]      [bold white] |  _  | [/bold white]  [bold cyan]_| |_  [/bold cyan]
[bold cyan]    \\/     [/bold cyan] [bold blue]|_____|[/bold blue]  [bold cyan] \\____/ [/bold cyan] [bold blue]|_____|[/bold blue]  [bold cyan]|______[/bold cyan]       [bold white] |_| |_| [/bold white] [bold cyan]|_____|[/bold cyan]

          [dim italic]Autonomous Web3 Smart Contract Auditor[/dim italic]
"""
    console.print(Panel(banner_text, title="[bold blue]VIGIL-AI[/bold blue]", border_style="cyan", expand=False))


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    show_welcome_banner()
    if ctx.invoked_subcommand is None:
        _run_interactive_shell()


@app.command()
def scan(
    path: Optional[str] = typer.Option(
        None,
        "--path",
        "-p",
        help="Local file or directory containing smart contracts (.sol / .vy).",
    ),
    url: Optional[str] = typer.Option(
        None,
        "--url",
        "-u",
        help="GitHub repository URL to clone and scan.",
    ),
    address: Optional[str] = typer.Option(
        None,
        "--address",
        "-a",
        help="Deployed contract address (e.g. 0x1234...).",
    ),
    chain: str = typer.Option(
        "ethereum",
        "--chain",
        "-c",
        help=f"Blockchain network. Supported: {', '.join(SUPPORTED_CHAINS)}.",
    ),
    api_key: str = typer.Option(
        "",
        "--api-key",
        help="Explorer API key (Etherscan, BscScan, ...). Increases rate limits.",
    ),
) -> None:
    """
    Scan a smart contract for security vulnerabilities.

    Exactly ONE input source must be provided:

      --path     Local file or project directory
      --url      GitHub repository URL
      --address  Deployed on-chain contract address
    """
    _run_scan(path, url, address, chain, api_key)


def _run_scan(
    path: Optional[str],
    url: Optional[str],
    address: Optional[str],
    chain: str,
    api_key: str,
) -> None:
    sources_given = sum(x is not None for x in [path, url, address])

    if sources_given == 0:
        err_console.print(
            "[bold red]Error:[/bold red] You must specify an input source.\n"
            "  [yellow]--path[/yellow]    Local file or directory\n"
            "  [yellow]--url[/yellow]     GitHub repository URL\n"
            "  [yellow]--address[/yellow] On-chain contract address"
        )
        raise typer.Exit(code=1)

    if sources_given > 1:
        err_console.print(
            "[bold red]Error:[/bold red] Only one input source is allowed per scan.\n"
            "  Please use [yellow]--path[/yellow], [yellow]--url[/yellow], "
            "or [yellow]--address[/yellow] - not multiple at once."
        )
        raise typer.Exit(code=1)

    if path is not None:
        _run_local_scan(path)
    elif url is not None:
        _run_github_scan(url)
    else:
        _run_chain_scan(address, chain, api_key)  # type: ignore[arg-type]


def _run_local_scan(path: str) -> None:
    console.print("[bold cyan]Input:[/bold cyan]  Local Path")
    console.print(f"[bold cyan]Target:[/bold cyan] {path}\n")

    loader = LocalLoader(path)
    ok, msg = loader.validate()
    if not ok:
        err_console.print(f"[bold red]Error:[/bold red] {msg}")
        raise typer.Exit(code=1)

    with console.status("[bold green]Scanning local files..."):
        contracts = loader.load()

    _print_contracts_table(contracts, source_label="Local Path")


def _run_github_scan(url: str) -> None:
    console.print("[bold cyan]Input:[/bold cyan]  GitHub URL")
    console.print(f"[bold cyan]Target:[/bold cyan] {url}\n")

    loader = GitHubLoader(url)
    ok, msg = loader.validate()
    if not ok:
        err_console.print(f"[bold red]Error:[/bold red] {msg}")
        raise typer.Exit(code=1)

    try:
        with console.status("[bold green]Cloning repository..."):
            contracts = loader.load()
    except RuntimeError as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)
    finally:
        loader.cleanup()

    _print_contracts_table(contracts, source_label="GitHub Repository")


def _run_chain_scan(address: str, chain: str, api_key: str) -> None:
    cfg = SUPPORTED_CHAINS.get(chain.lower(), {})
    explorer = cfg.get("explorer_name", chain)

    console.print("[bold cyan]Input:[/bold cyan]  On-Chain Address")
    console.print(f"[bold cyan]Chain:[/bold cyan]  {chain.capitalize()}  ({explorer})")
    console.print(f"[bold cyan]Target:[/bold cyan] {address}\n")

    loader = ChainLoader(address, chain, api_key)
    ok, msg = loader.validate()
    if not ok:
        err_console.print(f"[bold red]Error:[/bold red] {msg}")
        raise typer.Exit(code=1)

    try:
        with console.status(f"[bold green]Fetching source from {explorer}..."):
            contracts = loader.load()
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] Failed to fetch contract: {exc}")
        raise typer.Exit(code=1)

    if not contracts:
        err_console.print(
            "[bold red]Error:[/bold red] No verified source code found for this address.\n"
            f"  Make sure the contract is verified on {explorer}."
        )
        raise typer.Exit(code=1)

    _print_contracts_table(contracts, source_label=f"On-Chain ({chain.capitalize()})")


def _print_contracts_table(contracts: list, source_label: str) -> None:
    if not contracts:
        console.print("[bold yellow]Warning:[/bold yellow] No Solidity or Vyper files found.")
        return

    table = Table(
        title=f"[bold green]Contracts Found[/bold green] | Source: {source_label}",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("File Name", style="bold white")
    table.add_column("Language", justify="center")
    table.add_column("Size", justify="right", style="dim")

    for idx, contract in enumerate(contracts, start=1):
        lang_color = "yellow" if contract.language == "vyper" else "blue"
        size_str = f"{len(contract.content):,} chars"
        table.add_row(
            str(idx),
            contract.name,
            f"[{lang_color}]{contract.language.capitalize()}[/{lang_color}]",
            size_str,
        )

    console.print(table)
    console.print(
        f"\n[bold green]Found {len(contracts)} contract file(s).[/bold green]  "
        "[dim]AI audit engine coming soon...[/dim]\n"
    )


@dataclass
class ShellSession:
    path: Optional[str] = None
    url: Optional[str] = None
    address: Optional[str] = None
    chain: str = "ethereum"
    api_key: str = ""


def _run_interactive_shell() -> None:
    session = ShellSession()
    console.print("[bold cyan]Interactive mode enabled.[/bold cyan] Type [bold yellow]help[/bold yellow] for commands.")

    while True:
        try:
            raw = typer.prompt("[vigil-ai]", prompt_suffix=" > ")
        except (EOFError, KeyboardInterrupt):
            console.print("\n[bold yellow]Exiting interactive mode.[/bold yellow]")
            break

        line = raw.strip()
        if not line:
            continue

        try:
            parts = shlex.split(line)
        except ValueError as exc:
            err_console.print(f"[bold red]Error:[/bold red] {exc}")
            continue

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in {"exit", "quit", "q"}:
            console.print("[bold yellow]Goodbye.[/bold yellow]")
            break
        if cmd in {"help", "?"}:
            _print_shell_help()
            continue
        if cmd == "show":
            _print_shell_state(session)
            continue
        if cmd == "reset":
            session = ShellSession()
            console.print("[green]Session reset.[/green]")
            continue
        if cmd == "set":
            _handle_shell_set(session, args)
            continue
        if cmd == "scan":
            _run_shell_scan(session)
            continue
        if cmd == "clear":
            console.clear()
            continue

        err_console.print(f"[bold red]Error:[/bold red] Unknown command '{cmd}'. Type [yellow]help[/yellow].")


def _print_shell_help() -> None:
    console.print(
        "[bold cyan]Commands:[/bold cyan]\n"
        "  help                      Show this help\n"
        "  show                      Show current session values\n"
        "  set path <value>          Set local path source (clears url/address)\n"
        "  set url <value>           Set GitHub URL source (clears path/address)\n"
        "  set address <value>       Set on-chain address source (clears path/url)\n"
        f"  set chain <value>         Set chain ({', '.join(SUPPORTED_CHAINS)})\n"
        "  set api_key <value>       Set explorer API key\n"
        "  reset                     Clear all session values\n"
        "  scan                      Run scan using current session values\n"
        "  clear                     Clear terminal view\n"
        "  exit | quit               Exit interactive mode\n"
    )


def _print_shell_state(session: ShellSession) -> None:
    table = Table(title="Current Session", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Key", style="bold white")
    table.add_column("Value")
    table.add_row("path", session.path or "-")
    table.add_row("url", session.url or "-")
    table.add_row("address", session.address or "-")
    table.add_row("chain", session.chain)
    table.add_row("api_key", "***" if session.api_key else "-")
    console.print(table)


def _handle_shell_set(session: ShellSession, args: list[str]) -> None:
    if len(args) < 2:
        err_console.print("[bold red]Error:[/bold red] Usage: set <path|url|address|chain|api_key> <value>")
        return

    field = args[0].lower()
    value = " ".join(args[1:]).strip()
    if not value:
        err_console.print("[bold red]Error:[/bold red] Value cannot be empty.")
        return

    if field == "path":
        session.path = value
        session.url = None
        session.address = None
    elif field == "url":
        session.url = value
        session.path = None
        session.address = None
    elif field == "address":
        session.address = value
        session.path = None
        session.url = None
    elif field == "chain":
        chain = value.lower()
        if chain not in SUPPORTED_CHAINS:
            supported = ", ".join(SUPPORTED_CHAINS.keys())
            err_console.print(f"[bold red]Error:[/bold red] Unsupported chain. Use: {supported}")
            return
        session.chain = chain
    elif field in {"api_key", "apikey"}:
        session.api_key = value
    else:
        err_console.print(f"[bold red]Error:[/bold red] Unknown field '{field}'.")
        return

    console.print(f"[green]Set {field}.[/green]")


def _run_shell_scan(session: ShellSession) -> None:
    try:
        _run_scan(session.path, session.url, session.address, session.chain, session.api_key)
    except typer.Exit:
        return


if __name__ == "__main__":
    app()
