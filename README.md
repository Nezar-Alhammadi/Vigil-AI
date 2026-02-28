# Vigil-AI

Vigil-AI is a CLI tool for collecting smart-contract sources from:
- Local path
- GitHub repository
- On-chain verified contract address

It currently focuses on source loading and scan input preparation.

## Requirements

- Python 3.10+
- Git (needed for `--url` scans)

## Run Locally

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
python src/cli.py --help
```

Examples:

```bash
python src/cli.py scan --path ./contracts
python src/cli.py scan --url https://github.com/OpenZeppelin/openzeppelin-contracts
python src/cli.py scan --address 0x0000000000000000000000000000000000000000 --chain ethereum
```

## Run with Docker

Build image:

```bash
docker build -t vigil-ai .
```

Show help:

```bash
docker run --rm vigil-ai --help
```

Scan a local folder (mount your contracts folder):

```bash
docker run --rm -v "${PWD}:/work" vigil-ai scan --path /work/contracts
```

Windows PowerShell variant:

```powershell
docker run --rm -v "${PWD}:/work" vigil-ai scan --path /work/contracts
```

Scan a GitHub repository:

```bash
docker run --rm vigil-ai scan --url https://github.com/OpenZeppelin/openzeppelin-contracts
```

Scan on-chain address:

```bash
docker run --rm vigil-ai scan --address 0x0000000000000000000000000000000000000000 --chain ethereum
```

## Notes

- `src/ai_engine` and `src/auditor` are still placeholders.
- Current output lists discovered contract files and metadata.
