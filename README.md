<div align="center">

```
__      __ _____ ____  _      _             _    _____
\ \    / /|_   _/ ___|| |    | |           / \  |_   _|
 \ \  / /   | || |  _ | |    | |          / _ \   | |
  \ \/ /    | || | |_ || |   | |         / /_\ \  | |
   \  /    _| || |__| || |___| |____    /  ___  \ | |
    \/    |_____\_____|_______|______|  /_/     \_\|_|
```

**Autonomous Web3 Smart Contract Security Auditor**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-orange?style=for-the-badge)](./LICENSE)
[![OpenRouter](https://img.shields.io/badge/Powered%20by-OpenRouter-7C3AED?style=for-the-badge)](https://openrouter.ai/)
[![Slither](https://img.shields.io/badge/Analyzer-Slither-2563EB?style=for-the-badge)](https://github.com/crytic/slither)
[![Aderyn](https://img.shields.io/badge/Analyzer-Aderyn-A855F7?style=for-the-badge)](https://github.com/Cyfrin/aderyn)
[![Solidity](https://img.shields.io/badge/Solidity-%E2%9C%93-363636?style=for-the-badge&logo=solidity)](https://soliditylang.org/)
[![Vyper](https://img.shields.io/badge/Vyper-%E2%9C%93-1DB954?style=for-the-badge)](https://docs.vyperlang.org/)

</div>

---

## 🔍 What is Vigil-AI?

**Vigil-AI** is a command-line security auditing platform for Web3 smart contracts. It acts as an **aggregator** — orchestrating two industry-standard static analyzers ([Slither](https://github.com/crytic/slither) and [Aderyn](https://github.com/Cyfrin/aderyn)) in sequence, then feeding every finding into a large language model via [OpenRouter](https://openrouter.ai/) to produce a structured, professional-grade Markdown audit report.

Point Vigil-AI at a **local project directory**, a **GitHub repository URL**, or a **live on-chain contract address** — it handles everything else: cloning, smart dependency resolution, static analysis, AI-powered deep-dive with parallel LLM calls, PDF export, and automated patch application directly to your source files.

```
Input Source          Static Analysis          AI Engine                  Output
─────────────────     ──────────────────       ──────────────────────     ──────────────────────
Local Path      ─┐                         ┌─ claude-3.5-sonnet (def) ─► Audit_Report.md
GitHub URL      ─┼─► Slither + Aderyn ────►│  gpt-4o                  ─► Audit_Report.pdf
On-Chain Addr.  ─┘   (parallel per-finding) └─ gemini-1.5-pro          ─► Auto-patched sources
```

---

## ✨ Key Features

### 🏗️ Three Input Sources

| Source | Description |
|---|---|
| **`--path`** | Recursively scans a local directory or a single file for `.sol` / `.vy` contracts, automatically skipping `node_modules`, `lib`, `artifacts`, `cache`, and `out` folders |
| **`--url`** | Clones a GitHub repository (with `--recurse-submodules` and SSH→HTTPS URL rewriting), then runs a smart dependency resolver before analysis |
| **`--address`** | Fetches verified source code from a block explorer API (Etherscan, BscScan, etc.) with an automatic fallback to the [Sourcify](https://sourcify.dev/) decentralised registry |

### ⛓️ 7-Chain Support

| Chain | Explorer |
|---|---|
| Ethereum | Etherscan |
| BSC | BscScan |
| Polygon | PolygonScan |
| Arbitrum | Arbiscan |
| Optimism | Optimism Etherscan |
| Base | BaseScan |
| Avalanche | SnowTrace |

### 🔬 Dual Static Analysis Engine

- **Slither** — Trail of Bits' battle-tested Solidity/Vyper analyzer, invoked with JSON output mode and configurable `--filter-paths` for Focus Scan vs. Full Scan modes.
- **Aderyn** — Cyfrin's next-generation Rust-based analyzer. Its output is normalized into a unified finding schema shared with Slither, so both tools feed a single pipeline.
- All findings are **merged, sorted by severity** (High → Medium → Low → Informational → Optimization), and displayed in a Rich-formatted colour-coded table before the AI step.

### 🤖 Parallel AI Analysis Engine

- Connects to any model available on **OpenRouter** using the OpenAI-compatible SDK.
- Runs **up to 5 concurrent `ThreadPoolExecutor` workers** — one per finding — for fast, parallel LLM calls.
- Each call receives the exact vulnerable code lines with `@>` markers and ±5 lines of surrounding context, and fills a structured audit template covering:
  - **Impact** and **Likelihood** ratings
  - **Root Cause** description with annotated code snippet
  - **Proof of Concept** (conceptual Foundry test)
  - **Recommended Mitigation** as a `diff` block
- A live Rich progress bar tracks each parallel finding as it completes.
- Severity filtering via `config.yaml` controls which findings are sent to the AI (`high`, `medium`, or `low`).

### 🩹 Automated Auto-Fix Patcher

After the AI report is generated, Vigil-AI optionally parses every `### Recommended Mitigation` diff block from the report and **applies the patches directly to your local source files**, reporting a clear summary of successful and failed patches.

### 📄 PDF Export

Pass `--pdf` on the command line and Vigil-AI exports the final Markdown audit report to `Audit_Report.pdf` in your current working directory, in addition to `Audit_Report.md`.

### 🖥️ Interactive Shell

Run `vigil-ai` with no arguments to enter a persistent, stateful interactive shell — ideal for iterative auditing sessions without re-typing flags.

### 📦 Smart Dependency Resolver (GitHub mode)

When scanning a GitHub repository, Vigil-AI automatically:
1. Rewrites any SSH submodule URLs to HTTPS and syncs them
2. Initialises and updates all Git submodules recursively
3. Runs `make` if a `Makefile` is present
4. Runs `yarn install` or `npm install` if `package.json` is present
5. Scans all `.sol` files to detect which common libraries are imported (`@openzeppelin`, `forge-std`, `solmate`, `solady`, `chainlink`, `base64`) and downloads any that are missing — with **version-aware branch selection** for OpenZeppelin (Solidity 0.6 / 0.7 / 0.8)
6. Builds with `forge build` if `foundry.toml` is present
7. Compiles with `npx hardhat compile` if a Hardhat config is present

### 🎨 Rich Terminal UX

- Animated ASCII art welcome banner on startup
- Color-coded severity: 🔴 High · 🟡 Medium · 🟢 Low · 🔵 Optimization
- Rich panel-framed status messages at every scan stage
- Live spinners during cloning, dependency resolution, compilation, and AI analysis
- Interactive model-selection menu at runtime with config-default highlighting
- Rich tables for: contracts discovered, vulnerability report, shell help, and session state

---

## 📦 Installation

### Prerequisites

| Requirement | Purpose | Install |
|---|---|---|
| Python 3.11+ | Runtime | [python.org](https://www.python.org/downloads/) |
| Git | GitHub repo cloning | System package manager |
| Slither | Static analysis (Solidity/Vyper) | `pip install slither-analyzer` |
| Aderyn | Static analysis (Solidity) | See command below |
| Foundry `forge` | Optional — builds Foundry projects | [getfoundry.sh](https://getfoundry.sh/) |

**Install Aderyn:**
```bash
curl -L https://raw.githubusercontent.com/Cyfrin/aderyn/main/cyfrinup/install | bash
cyfrinup
```

### Install Vigil-AI

```bash
# 1. Clone the repository
git clone https://github.com/your-org/vigil-ai.git
cd vigil-ai

# 2. Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows (cmd/PowerShell)

# 3. Install Python dependencies
pip install -r requirements.txt
```

### Docker

A `Dockerfile` is included. The image is based on `python:3.11-slim` with `git` pre-installed for GitHub cloning. Note that Slither and Aderyn binaries are not bundled — extend the `Dockerfile` or mount the binaries if needed.

```bash
# Build the image
docker build -t vigil-ai .

# Scan a local directory (mount your contracts folder)
docker run --rm \
  -v /absolute/path/to/contracts:/contracts \
  -e OPENROUTER_API_KEY=sk-or-... \
  vigil-ai scan --path /contracts

# Scan a GitHub repository
docker run --rm \
  -e OPENROUTER_API_KEY=sk-or-... \
  vigil-ai scan --url https://github.com/owner/repo

# Scan an on-chain address
docker run --rm \
  -e OPENROUTER_API_KEY=sk-or-... \
  vigil-ai scan --address 0x... --chain ethereum

# Windows PowerShell (mount current directory)
docker run --rm -v "${PWD}:/work" vigil-ai scan --path /work/contracts
```

---

## 🚀 Usage / Quick Start

### Non-Interactive (Single-Command) Scans

```bash
# --- Local source ---
# Scan a directory (Focus Scan by default — libs/tests excluded)
python src/cli.py scan --path ./src

# Scan a single contract file
python src/cli.py scan --path ./src/Token.sol

# Full Scan — include lib/, test/, node_modules/
python src/cli.py scan --path ./src --full

# --- GitHub ---
# Clone, resolve deps, and scan
python src/cli.py scan --url https://github.com/OpenZeppelin/openzeppelin-contracts

# Clone and scan, export a PDF report
python src/cli.py scan --url https://github.com/owner/repo --pdf

# --- On-Chain ---
# Scan a verified Ethereum mainnet contract
python src/cli.py scan --address 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48

# Scan on Polygon with your own explorer key
python src/cli.py scan \
  --address 0x... \
  --chain polygon \
  --api-key YOUR_POLYGONSCAN_KEY
```

### Scan Flags Reference

| Flag | Short | Default | Description |
|---|---|---|---|
| `--path` | `-p` | — | Local file or directory of `.sol` / `.vy` contracts |
| `--url` | `-u` | — | GitHub repository URL to clone and scan |
| `--address` | `-a` | — | Deployed contract address (e.g. `0xA0b8...`) |
| `--chain` | `-c` | `ethereum` | Target chain (`ethereum`, `bsc`, `polygon`, `arbitrum`, `optimism`, `base`, `avalanche`) |
| `--api-key` | — | — | Block explorer API key — increases rate limits |
| `--full` | — | `false` | Include libraries, tests, and scripts in the scan |
| `--pdf` | — | `false` | Export the final AI audit report as a PDF |

> Exactly **one** of `--path`, `--url`, or `--address` must be provided per scan. Combining more than one is an error.

---

### Interactive Shell

Run Vigil-AI with no arguments to enter the interactive shell:

```bash
python src/cli.py
```

```
[vigil-ai] > help
```

| Command | Description |
|---|---|
| `help` / `?` | Show the interactive command menu |
| `show` | Display all current session values |
| `set path <value>` | Set a local directory as the scan target (clears url / address) |
| `set url <value>` | Set a GitHub URL as the scan target (clears path / address) |
| `set address <value>` | Set an on-chain address as the scan target (clears path / url) |
| `set chain <value>` | Set the target chain |
| `set api_key <value>` | Set a block explorer API key for this session |
| `set full <true/false>` | Toggle between Focus Scan and Full Scan |
| `reset` | Clear all session values |
| `scan` | Execute a scan with the current session values |
| `clear` | Clear the terminal |
| `exit` / `quit` / `q` | Exit the shell |

**Example session:**

```
[vigil-ai] > set url https://github.com/Cyfrin/audit-data
[vigil-ai] > set chain ethereum
[vigil-ai] > set full false
[vigil-ai] > scan
```

---

### AI Model Selection

When generating an AI report, Vigil-AI presents a live selection menu:

```
Select an AI Model for the Audit Report:
  [1] anthropic/claude-3.5-sonnet  (Config Default)
  [2] openai/gpt-4o
  [3] google/gemini-1.5-pro
  [4] meta-llama/llama-3-70b-instruct
  [5] Custom (Type any OpenRouter model name)
```

The default highlighted in the menu is driven by the `llm.model` value in `config.yaml`. Select option `5` to enter any model identifier available on OpenRouter.

---

## ⚙️ Configuration

### `config.yaml`

A global configuration file at the project root controls default behaviour. All fields are optional — sensible defaults apply if the file is absent.

```yaml
llm:
  provider: "openai"        # openai | anthropic | google
  model: "gpt-4-turbo"      # Default model pre-selected in the menu
  api_key: ""               # Set via env var OPENAI_API_KEY instead
  temperature: 0.2

audit:
  severity_level: "medium"  # Controls which findings are sent to the AI LLM:
                            #   high   → only High severity findings
                            #   medium → High + Medium findings (default)
                            #   low    → High + Medium + Low findings
  report_format: "markdown" # markdown | json

supported_languages:
  - "solidity"
  - "vyper"

# Block explorer API keys (optional — increases rate limits)
# These can also be set via environment variables:
#   ETHERSCAN_API_KEY, BSCSCAN_API_KEY, POLYGONSCAN_API_KEY, etc.
explorer_api_keys:
  ethereum:  ""   # https://etherscan.io/myapikey
  bsc:       ""   # https://bscscan.com/myapikey
  polygon:   ""   # https://polygonscan.com/myapikey
  arbitrum:  ""   # https://arbiscan.io/myapikey
  optimism:  ""   # https://optimistic.etherscan.io/myapikey
  base:      ""   # https://basescan.org/myapikey
  avalanche: ""   # https://snowtrace.io/myapikey
```

### OpenRouter API Key

Vigil-AI resolves your OpenRouter key using this priority order:

1. **`OPENROUTER_API_KEY` environment variable** (highest priority)
2. **`~/.vigil-ai/openrouter_key`** file (created automatically on first use)

On the first run that requires AI analysis and no key is found, Vigil-AI will prompt you to enter it and save it securely to `~/.vigil-ai/openrouter_key` for future sessions.

```bash
# Option A — environment variable (recommended for CI/CD)
export OPENROUTER_API_KEY=sk-or-v1-...

# Option B — key file
mkdir -p ~/.vigil-ai
echo "sk-or-v1-..." > ~/.vigil-ai/openrouter_key
```

Get a free API key at [openrouter.ai/keys](https://openrouter.ai/keys).

---

## 📂 Project Structure

```
vigil-ai/
├── src/
│   ├── cli.py                  # CLI entry point, interactive shell, scan orchestration
│   ├── config_loader.py        # config.yaml loader utility
│   ├── ai_engine/
│   │   ├── __init__.py
│   │   ├── analyzer.py         # OpenRouter AI engine — parallel LLM calls & report assembly
│   │   └── patcher.py          # Auto-fix patcher — applies diff blocks to source files
│   └── inputs/
│       ├── __init__.py
│       ├── local_loader.py     # Local file/directory loader (.sol / .vy)
│       ├── github_loader.py    # GitHub clone + smart dependency resolver
│       └── chain_loader.py     # On-chain fetcher (Etherscan API + Sourcify fallback)
├── config.yaml                 # Global configuration file
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Container image definition
└── LICENSE                     # Business Source License 1.1
```

---

## 🔄 Internal Workflow

```
vigil-ai scan [--path | --url | --address]
         │
         ├─ LocalLoader      ─► walk .sol/.vy files
         ├─ GitHubLoader     ─► clone → fix gitmodules → install deps → build
         └─ ChainLoader      ─► Etherscan API ──► (fallback) Sourcify
                │
                ▼
        ┌──────────────────────────────────────────┐
        │         Contracts Discovered Table        │
        │   (file name, language, size)             │
        └──────────────────┬───────────────────────┘
                           │
               ┌───────────▼────────────┐
               │  Slither  (JSON mode)  │
               │  Aderyn   (JSON mode)  │
               └───────────┬────────────┘
                           │  all findings merged + normalized
                           ▼
              ┌────────────────────────────┐
              │  Vulnerability Table       │
              │  (sorted High→Info)        │
              └────────────┬───────────────┘
                           │  user confirms AI report
                           ▼
          ┌────────────────────────────────────────┐
          │  AI Engine  (OpenRouter via OpenAI SDK) │
          │                                        │
          │  ┌─ worker 1 ─┐  ┌─ worker 2 ─┐  ... │
          │  │ finding #1  │  │ finding #2  │      │
          │  │ +code ctx   │  │ +code ctx   │      │
          │  │ → LLM call  │  │ → LLM call  │      │
          │  └─────────────┘  └─────────────┘      │
          │          (up to 5 parallel workers)     │
          └────────────────┬───────────────────────┘
                           │
               ┌───────────▼─────────────┐
               │    Audit_Report.md       │   (always written)
               │    Audit_Report.pdf      │   (with --pdf flag)
               └───────────┬─────────────┘
                           │  user confirms auto-fix
                           ▼
               ┌───────────────────────────┐
               │  Patcher                  │
               │  parse diff blocks  ──►   │
               │  apply to .sol files      │
               └───────────────────────────┘
```

---

## 📋 Python Dependencies

| Package | Version | Purpose |
|---|---|---|
| `typer` | ≥ 0.12.0 | CLI framework with argument parsing |
| `rich` | 13.7.0 | Terminal UI, tables, progress bars, panels |
| `requests` | 2.31.0 | HTTP calls to block explorers and Sourcify |
| `slither-analyzer` | ≥ 0.10.0 | Solidity / Vyper static analyzer |
| `openai` | ≥ 1.0.0 | OpenRouter-compatible API client |
| `PyYAML` | ≥ 6.0.1 | `config.yaml` parsing |
| `md2pdf` | ≥ 1.0.1 | Markdown → PDF export |

---

## 📄 License

**Business Source License 1.1**

| Parameter | Value |
|---|---|
| **Licensed Work** | Vigil-AI (and its associated source code) |
| **Change Date** | 2029-01-01 |
| **Change License** | Apache License, Version 2.0 |
| **Additional Use Grant** | Non-commercial use and personal research are permitted. Production use by commercial entities requires a separate license. |

After the Change Date of **January 1, 2029**, this software will be made available under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

See the full [LICENSE](./LICENSE) file for complete terms.

---

<div align="center">

Built with ❤️ for the Web3 security community.

</div>
