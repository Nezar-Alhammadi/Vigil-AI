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
               --full              Scan everything including libraries
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Optional

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

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
[bold cyan]\ \    / / [/bold cyan] [bold blue]|_   _|[/bold blue]  [bold cyan] / __ \ [/bold cyan] [bold blue]|_   _|[/bold blue]  [bold cyan]| |     [/bold cyan]      [bold white]  / _ \  [/bold white] [bold cyan]|_   _| [/bold cyan]
[bold cyan] \ \  / /  [/bold cyan]   [bold blue]| |  [/bold blue]  [bold cyan]| |  \_|[/bold cyan]   [bold blue]| |  [/bold blue]  [bold cyan]| |     [/bold cyan]      [bold white] | | | | [/bold white]   [bold cyan]| |   [/bold cyan]
[bold cyan]  \ \/ /   [/bold cyan]   [bold blue]| |  [/bold blue]  [bold cyan]| | __  [/bold cyan]   [bold blue]| |  [/bold blue]  [bold cyan]| |     [/bold cyan]      [bold white] | |_| | [/bold white]   [bold cyan]| |   [/bold cyan]
[bold cyan]   \  /    [/bold cyan]  [bold blue]_| |_ [/bold blue]  [bold cyan]| |_\ \ [/bold cyan]  [bold blue]_| |_ [/bold blue]  [bold cyan]| |____ [/bold cyan]      [bold white] |  _  | [/bold white]  [bold cyan]_| |_  [/bold cyan]
[bold cyan]    \/     [/bold cyan] [bold blue]|_____|[/bold blue]  [bold cyan] \____/ [/bold cyan] [bold blue]|_____|[/bold blue]  [bold cyan]|______[/bold cyan]       [bold white] |_| |_| [/bold white] [bold cyan]|_____|[/bold cyan]

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
    full: bool = typer.Option(
        False,
        "--full",
        help="Run a full scan including libraries and test folders (e.g. lib/, test/).",
    ),
) -> None:
    """
    Scan a smart contract for security vulnerabilities.

    Exactly ONE input source must be provided:

      --path     Local file or project directory
      --url      GitHub repository URL
      --address  Deployed on-chain contract address
    """
    _run_scan(path, url, address, chain, api_key, full)


def _run_scan(
    path: Optional[str],
    url: Optional[str],
    address: Optional[str],
    chain: str,
    api_key: str,
    full: bool,
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
        _run_local_scan(path, full)
    elif url is not None:
        _run_github_scan(url, full)
    else:
        _run_chain_scan(address, chain, api_key, full)  # type: ignore[arg-type]


def _run_local_scan(path: str, full: bool) -> None:
    console.print(Panel(f"[bold cyan]Input:[/bold cyan]  Local Path\n[bold cyan]Target:[/bold cyan] {path}", border_style="green", expand=False))

    loader = LocalLoader(path)
    ok, msg = loader.validate()
    if not ok:
        err_console.print(f"[bold red]Error:[/bold red] {msg}")
        raise typer.Exit(code=1)

    with console.status("[bold green]Scanning local files..."):
        contracts = loader.load()

    _print_contracts_table(contracts, source_label="Local Path")
    _run_slither(path, full)


def _run_github_scan(url: str, full: bool) -> None:
    console.print(Panel(f"[bold cyan]Input:[/bold cyan]  GitHub URL\n[bold cyan]Target:[/bold cyan] {url}", border_style="blue", expand=False))

    loader = GitHubLoader(url)
    ok, msg = loader.validate()
    if not ok:
        err_console.print(f"[bold red]Error:[/bold red] {msg}")
        raise typer.Exit(code=1)

    try:
        with console.status("[bold green]Cloning repository & installing dependencies..."):
            contracts = loader.load()
            repo_path = loader.repo_path
    except RuntimeError as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)
    else:
        _print_contracts_table(contracts, source_label="GitHub Repository")
        if repo_path:
            _run_slither(repo_path, full)
    finally:
        loader.cleanup()


def _run_chain_scan(address: str, chain: str, api_key: str, full: bool) -> None:
    cfg = SUPPORTED_CHAINS.get(chain.lower(), {})
    explorer = cfg.get("explorer_name", chain)

    info = (
        f"[bold cyan]Input:[/bold cyan]  On-Chain Address\n"
        f"[bold cyan]Chain:[/bold cyan]  {chain.capitalize()} ({explorer})\n"
        f"[bold cyan]Target:[/bold cyan] {address}"
    )
    console.print(Panel(info, border_style="magenta", expand=False))

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
    _run_slither_for_chain_contracts(contracts, full)


def _print_contracts_table(contracts: list, source_label: str) -> None:
    if not contracts:
        console.print("[bold yellow]Warning:[/bold yellow] No Solidity or Vyper files found.")
        return

    table = Table(
        title=f"[bold green]Contracts Found[/bold green] | Source: {source_label}",
        box=box.HEAVY_EDGE,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("File Name", style="bold white")
    table.add_column("Language", justify="center")
    table.add_column("Size", justify="right", style="dim")

    for idx, contract in enumerate(contracts, start=1):
        if contract.language == "vyper":
            lang_str = "[yellow]Vyper[/yellow]"
        else:
            lang_str = "[blue]Solidity[/blue]"
            
        size_str = f"{len(contract.content):,} chars"
        table.add_row(
            str(idx),
            contract.name,
            lang_str,
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
    full: bool = False


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
    table = Table(title="[bold cyan]Interactive Shell Commands[/bold cyan]", box=box.SIMPLE_HEAVY, header_style="bold yellow")
    table.add_column("Command", style="bold green")
    table.add_column("Description", style="white")

    table.add_row("help / ?", "Show this help menu")
    table.add_row("show", "Show current session values")
    table.add_row("set path <value>", "Set local path source (clears url/address)")
    table.add_row("set url <value>", "Set GitHub URL source (clears path/address)")
    table.add_row("set address <value>", "Set on-chain address source (clears path/url)")
    table.add_row("set chain <value>", f"Set chain ({', '.join(SUPPORTED_CHAINS)})")
    table.add_row("set api_key <value>", "Set explorer API key")
    table.add_row("set full <true/false>", "Toggle Full Scan vs Focus Scan (ignore libs)")
    table.add_row("reset", "Clear all session values")
    table.add_row("scan", "Run scan using current session values")
    table.add_row("clear", "Clear terminal view")
    table.add_row("exit / quit / q", "Exit interactive mode")

    console.print(table)


def _print_shell_state(session: ShellSession) -> None:
    table = Table(title="Current Session", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Key", style="bold white")
    table.add_column("Value")
    
    table.add_row("path", session.path or "[dim]-[/dim]")
    table.add_row("url", session.url or "[dim]-[/dim]")
    table.add_row("address", session.address or "[dim]-[/dim]")
    table.add_row("chain", session.chain)
    table.add_row("api_key", "***" if session.api_key else "[dim]-[/dim]")
    table.add_row("full scan", "[green]True[/green]" if session.full else "[yellow]False[/yellow]")
    console.print(table)


def _handle_shell_set(session: ShellSession, args: list[str]) -> None:
    if len(args) < 2:
        err_console.print("[bold red]Error:[/bold red] Usage: set <path|url|address|chain|api_key|full> <value>")
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
    elif field == "full":
        session.full = value.lower() in {"true", "1", "yes", "y"}
    else:
        err_console.print(f"[bold red]Error:[/bold red] Unknown field '{field}'.")
        return

    console.print(f"[green]Set {field} successfully.[/green]")


def _run_shell_scan(session: ShellSession) -> None:
    try:
        _run_scan(session.path, session.url, session.address, session.chain, session.api_key, session.full)
    except typer.Exit:
        return


def _run_slither(target: str, full: bool) -> None:
    slither_bin = shutil.which("slither")
    if not slither_bin:
        err_console.print(
            "[bold yellow]Warning:[/bold yellow] Slither is not installed or not in PATH.\n"
            "Install with: [cyan]pip install slither-analyzer[/cyan]"
        )
        return

    # إنشاء ملف مؤقت لحفظ تقرير JSON من Slither
    fd, tmp_json_path = tempfile.mkstemp(suffix=".json", prefix="vigil_slither_")
    os.close(fd)

    cmd = [slither_bin, target, "--json", tmp_json_path]
    
    # الفلترة لتجاهل المكتبات
    if not full:
        filter_regex = "(lib/|node_modules/|test/|tests/|script/|scripts/|mock/|mocks/|@openzeppelin/)"
        cmd.extend(["--filter-paths", filter_regex])

    with console.status(f"[bold cyan]Running Slither analysis on [white]{target}[/white]..."):
        if not full:
            console.print("[dim]Mode: [bold green]Focus Scan[/bold green] (Ignoring libraries and test files. Use --full to scan all)[/dim]")
        else:
            console.print("[dim]Mode: [bold yellow]Full Scan[/bold yellow] (Including all libraries and dependencies)[/dim]")

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            err_console.print("[bold red]Error:[/bold red] Slither timed out.")
            _cleanup_temp_file(tmp_json_path)
            return
        except Exception as exc:
            err_console.print(f"[bold red]Error:[/bold red] Failed to run Slither: {exc}")
            _cleanup_temp_file(tmp_json_path)
            return

    # محاولة استخراج النتائج من ملف JSON
    parsed_successfully = False
    detectors = []
    
    if os.path.exists(tmp_json_path) and os.path.getsize(tmp_json_path) > 0:
        try:
            with open(tmp_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "results" in data and "detectors" in data["results"]:
                    detectors = data["results"]["detectors"]
                    parsed_successfully = True
        except Exception:
            pass
            
    _cleanup_temp_file(tmp_json_path)

    # في حال فشل الفحص تماماً (مثلاً مشكلة في الكومبايلر ولم يتم إنشاء JSON)
    if not parsed_successfully and result.returncode != 0:
        output_text = result.stdout.strip()
        if _looks_like_missing_foundry_deps(output_text):
            err_console.print(
                "[bold yellow]Hint:[/bold yellow] This repository likely needs Foundry dependencies "
                "(missing `lib/` imports). Try running [cyan]forge install[/cyan] inside the repo "
                "or ensure submodules/dependencies are present."
            )
        else:
            slither_error = Panel(
                Text.from_ansi(output_text), 
                title="[bold red]Compilation or Slither Error[/bold red]", 
                border_style="red"
            )
            console.print(slither_error)
        return

    # طباعة الجدول المنظم إذا تم استخراج الثغرات بنجاح
    if not detectors:
        console.print("\n[bold green]Slither finished successfully with no issues found.[/bold green] ✅")
    else:
        _print_slither_table(detectors)


def _print_slither_table(detectors: list) -> None:
    # ترتيب مستويات الخطورة من الأعلى إلى الأقل
    impact_weights = {
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Informational": 4,
        "Optimization": 5
    }
    
    # فرز القائمة بناءً على مستوى الخطورة
    detectors.sort(key=lambda x: impact_weights.get(x.get("impact", "Informational"), 99))

    table = Table(
        title="\n[bold orange3]Slither Vulnerability Report[/bold orange3]",
        box=box.HEAVY_EDGE,
        show_lines=True,
        header_style="bold cyan"
    )
    
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Detector (Rule)", style="bold white", width=25)
    table.add_column("Description / Location", style="dim")

    for d in detectors:
        impact = d.get("impact", "Informational")
        check = d.get("check", "Unknown")
        description = d.get("description", "").strip()

        # تنسيق الألوان بناءً على الخطورة
        if impact == "High":
            impact_str = "[bold red]High[/bold red]"
        elif impact == "Medium":
            impact_str = "[bold yellow]Medium[/bold yellow]"
        elif impact == "Low":
            impact_str = "[bold green]Low[/bold green]"
        elif impact == "Optimization":
            impact_str = "[bold blue]Optimization[/bold blue]"
        else:
            impact_str = f"[bold cyan]{impact}[/bold cyan]"

        # تنظيف الوصف من المسافات والفراغات الزائدة ليكون أنيقاً داخل الجدول
        clean_desc = " ".join(description.split())
        
        # لعدم جعل الوصف طويلاً جداً ومزعجاً، يمكننا اقتصاص أول سطر فقط
        # (Slither عادة يضع السطر الأول كخلاصة)
        short_desc = description.split('\n')[0] if '\n' in description else clean_desc

        table.add_row(impact_str, check, short_desc)

    console.print(table)
    console.print(f"\n[bold orange3]Total issues found: {len(detectors)}[/bold orange3]")


def _cleanup_temp_file(filepath: str) -> None:
    if os.path.exists(filepath):
        try:
            os.remove(filepath)
        except OSError:
            pass


def _run_slither_for_chain_contracts(contracts: list, full: bool) -> None:
    with tempfile.TemporaryDirectory(prefix="vigil_chain_") as tmp_dir:
        root = Path(tmp_dir)
        for contract in contracts:
            rel_path = _normalize_contract_rel_path(contract.path, contract.name)
            file_path = root / rel_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(contract.content, encoding="utf-8")

        _run_slither(str(root), full)


def _normalize_contract_rel_path(path: str, fallback_name: str) -> Path:
    normalized = path.replace("\\", "/").strip()
    if not normalized:
        normalized = fallback_name

    parts = [part for part in PurePosixPath(normalized).parts if part not in {"", ".", ".."}]
    if not parts:
        parts = [fallback_name]

    return Path(*parts)


def _looks_like_missing_foundry_deps(stderr: str) -> bool:
    markers = [
        "Unable to resolve imports",
        "Source \"lib/",
        "No such file or directory",
        "forge' returned non-zero exit code",
        "InvalidCompilation",
    ]
    return any(marker in stderr for marker in markers)


if __name__ == "__main__":
    app()