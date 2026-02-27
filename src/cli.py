"""
Vigil-AI  –  Command-Line Interface
====================================
Entry point for the Vigil-AI autonomous Web3 security auditor.

Commands
--------
  vigil-ai                         Show welcome banner
  vigil-ai scan --path   <dir>     Scan a local file or directory
  vigil-ai scan --url    <url>     Clone a GitHub repo and scan it
  vigil-ai scan --address <addr>   Fetch a deployed contract and scan it
               --chain   <chain>   (default: ethereum)
               --api-key <key>     Optional explorer API key
"""

from __future__ import annotations

import sys
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from inputs import LocalLoader, GitHubLoader, ChainLoader, SUPPORTED_CHAINS

# ── App setup ────────────────────────────────────────────────────────────────

app = typer.Typer(
    name="vigil-ai",
    help="Vigil-AI: The Autonomous Web3 Security Auditor",
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


# ── Welcome banner ───────────────────────────────────────────────────────────

def show_welcome_banner() -> None:
    banner_text = """
[bold cyan]__      __ [/bold cyan]  [bold blue]_____ [/bold blue]  [bold cyan]  ____  [/bold cyan]  [bold blue]_____ [/bold blue]  [bold cyan] _      [/bold cyan]      [bold white]   ___   [/bold white] [bold cyan] ____  [/bold cyan]
[bold cyan]\ \    / / [/bold cyan] [bold blue]|_   _|[/bold blue]  [bold cyan] / __ \ [/bold cyan] [bold blue]|_   _|[/bold blue]  [bold cyan]| |     [/bold cyan]      [bold white]  / _ \  [/bold white] [bold cyan]|_   _| [/bold cyan]
[bold cyan] \ \  / /  [/bold cyan]   [bold blue]| |  [/bold blue]  [bold cyan]| |  \_|[/bold cyan]   [bold blue]| |  [/bold blue]  [bold cyan]| |     [/bold cyan]      [bold white] | | | | [/bold white]   [bold cyan]| |   [/bold cyan]
[bold cyan]  \ \/ /   [/bold cyan]   [bold blue]| |  [/bold blue]  [bold cyan]| | __  [/bold cyan]   [bold blue]| |  [/bold blue]  [bold cyan]| |     [/bold cyan]      [bold white] | |_| | [/bold white]   [bold cyan]| |   [/bold cyan]
[bold cyan]   \  /    [/bold cyan]  [bold blue]_| |_ [/bold blue]  [bold cyan]| |_\ \ [/bold cyan]  [bold blue]_| |_ [/bold blue]  [bold cyan]| |____ [/bold cyan]      [bold white] |  _  | [/bold white]  [bold cyan]_| |_  [/bold cyan]
[bold cyan]    \/     [/bold cyan] [bold blue]|_____|[/bold blue]  [bold cyan] \____/ [/bold cyan] [bold blue]|_____|[/bold blue]  [bold cyan]|______[/bold cyan]       [bold white] |_| |_| [/bold white] [bold cyan]|_____|[/bold cyan]

          [dim italic]Autonomous Web3 Smart Contract Auditor[/dim italic]
"""
    console.print(Panel(banner_text, title="[bold blue]🛡️ VIGIL-AI[/bold blue]", border_style="cyan", expand=False))
    console.print("\n[bold green]Ready to audit![/bold green] Type [bold yellow]--help[/bold yellow] to see available commands.\n")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    show_welcome_banner()


# ── scan command ─────────────────────────────────────────────────────────────

@app.command()
def scan(
    path: Optional[str] = typer.Option(
        None,
        "--path", "-p",
        help="Local file or directory containing smart contracts (.sol / .vy).",
    ),
    url: Optional[str] = typer.Option(
        None,
        "--url", "-u",
        help="GitHub repository URL to clone and scan.",
    ),
    address: Optional[str] = typer.Option(
        None,
        "--address", "-a",
        help="Deployed contract address (e.g. 0x1234...).",
    ),
    chain: str = typer.Option(
        "ethereum",
        "--chain", "-c",
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

    \b
      --path     Local file or project directory
      --url      GitHub repository URL
      --address  Deployed on-chain contract address
    """
    # ── Validate: exactly one input source ──────────────────────────────────
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
            "or [yellow]--address[/yellow] — not multiple at once."
        )
        raise typer.Exit(code=1)

    # ── Route to the correct loader ──────────────────────────────────────────
    if path is not None:
        _run_local_scan(path)
    elif url is not None:
        _run_github_scan(url)
    else:
        _run_chain_scan(address, chain, api_key)  # type: ignore[arg-type]


# ── Scan runners ─────────────────────────────────────────────────────────────

def _run_local_scan(path: str) -> None:
    console.print(f"[bold cyan]Input:[/bold cyan]  Local Path")
    console.print(f"[bold cyan]Target:[/bold cyan] {path}\n")

    loader = LocalLoader(path)
    ok, msg = loader.validate()
    if not ok:
        err_console.print(f"[bold red]Error:[/bold red] {msg}")
        raise typer.Exit(code=1)

    with console.status("[bold green]Scanning local files…"):
        contracts = loader.load()

    _print_contracts_table(contracts, source_label="Local Path")


def _run_github_scan(url: str) -> None:
    console.print(f"[bold cyan]Input:[/bold cyan]  GitHub URL")
    console.print(f"[bold cyan]Target:[/bold cyan] {url}\n")

    loader = GitHubLoader(url)
    ok, msg = loader.validate()
    if not ok:
        err_console.print(f"[bold red]Error:[/bold red] {msg}")
        raise typer.Exit(code=1)

    try:
        with console.status("[bold green]Cloning repository…"):
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

    console.print(f"[bold cyan]Input:[/bold cyan]  On-Chain Address")
    console.print(f"[bold cyan]Chain:[/bold cyan]  {chain.capitalize()}  ({explorer})")
    console.print(f"[bold cyan]Target:[/bold cyan] {address}\n")

    loader = ChainLoader(address, chain, api_key)
    ok, msg = loader.validate()
    if not ok:
        err_console.print(f"[bold red]Error:[/bold red] {msg}")
        raise typer.Exit(code=1)

    try:
        with console.status(f"[bold green]Fetching source from {explorer}…"):
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


# ── Shared display ────────────────────────────────────────────────────────────

def _print_contracts_table(contracts: list, source_label: str) -> None:
    if not contracts:
        console.print("[bold yellow]Warning:[/bold yellow] No Solidity or Vyper files found.")
        return

    table = Table(
        title=f"[bold green]Contracts Found[/bold green]  ·  Source: {source_label}",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("File Name", style="bold white")
    table.add_column("Language", justify="center")
    table.add_column("Size", justify="right", style="dim")

    for idx, c in enumerate(contracts, start=1):
        lang_color = "yellow" if c.language == "vyper" else "blue"
        size_str = f"{len(c.content):,} chars"
        table.add_row(
            str(idx),
            c.name,
            f"[{lang_color}]{c.language.capitalize()}[/{lang_color}]",
            size_str,
        )

    console.print(table)
    console.print(
        f"\n[bold green]✔ Found {len(contracts)} contract file(s).[/bold green]  "
        "[dim]AI audit engine coming soon…[/dim]\n"
    )


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
