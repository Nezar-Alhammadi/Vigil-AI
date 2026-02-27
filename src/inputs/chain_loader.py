"""
On-Chain Contract Loader
------------------------
Fetches verified smart contract source code from a deployed contract address.

Strategy:
  1. Try Etherscan-compatible explorer API  (requires API key for full rate-limits)
  2. Fall back to Sourcify decentralised registry (no key needed)

Supported chains: ethereum, bsc, polygon, arbitrum, optimism, base, avalanche
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Tuple

import requests

from .local_loader import ContractFile


# ── Chain registry ──────────────────────────────────────────────────────────

SUPPORTED_CHAINS: Dict[str, dict] = {
    "ethereum": {
        "chain_id": 1,
        "explorer_api": "https://api.etherscan.io/api",
        "explorer_name": "Etherscan",
    },
    "bsc": {
        "chain_id": 56,
        "explorer_api": "https://api.bscscan.com/api",
        "explorer_name": "BscScan",
    },
    "polygon": {
        "chain_id": 137,
        "explorer_api": "https://api.polygonscan.com/api",
        "explorer_name": "PolygonScan",
    },
    "arbitrum": {
        "chain_id": 42161,
        "explorer_api": "https://api.arbiscan.io/api",
        "explorer_name": "Arbiscan",
    },
    "optimism": {
        "chain_id": 10,
        "explorer_api": "https://api-optimistic.etherscan.io/api",
        "explorer_name": "Optimism Etherscan",
    },
    "base": {
        "chain_id": 8453,
        "explorer_api": "https://api.basescan.org/api",
        "explorer_name": "BaseScan",
    },
    "avalanche": {
        "chain_id": 43114,
        "explorer_api": "https://api.snowtrace.io/api",
        "explorer_name": "SnowTrace",
    },
}

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_SOURCIFY_BASE = "https://sourcify.dev/server/files/any"

# ── Loader ───────────────────────────────────────────────────────────────────

class ChainLoader:
    """Fetches on-chain verified source code for a deployed smart contract."""

    def __init__(self, address: str, chain: str, api_key: str = ""):
        self.address = address.strip()
        self.chain = chain.lower().strip()
        self.api_key = api_key

    def validate(self) -> Tuple[bool, str]:
        if not _ADDRESS_RE.match(self.address):
            return False, (
                f"'{self.address}' is not a valid EVM contract address.\n"
                "  Expected format: 0x followed by 40 hex characters."
            )
        if self.chain not in SUPPORTED_CHAINS:
            supported = ", ".join(SUPPORTED_CHAINS.keys())
            return False, (
                f"Unsupported chain '{self.chain}'.\n"
                f"  Supported chains: {supported}"
            )
        return True, ""

    def load(self) -> List[ContractFile]:
        # 1️⃣  Etherscan-compatible explorer
        try:
            contracts = self._from_etherscan()
            if contracts:
                return contracts
        except Exception:
            pass

        # 2️⃣  Sourcify fallback
        return self._from_sourcify()

    # ── Private helpers ──────────────────────────────────────────────────────

    def _from_etherscan(self) -> List[ContractFile]:
        cfg = SUPPORTED_CHAINS[self.chain]
        params: dict = {
            "module": "contract",
            "action": "getsourcecode",
            "address": self.address,
        }
        if self.api_key:
            params["apikey"] = self.api_key

        resp = requests.get(cfg["explorer_api"], params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "1":
            return []

        result = data["result"][0]
        raw_source: str = result.get("SourceCode", "")
        contract_name: str = result.get("ContractName", "Contract")

        if not raw_source:
            return []

        # Etherscan wraps multi-file JSON in double braces {{ … }}
        if raw_source.startswith("{{"):
            return self._parse_standard_json(raw_source[1:-1], contract_name)
        if raw_source.startswith("{"):
            return self._parse_standard_json(raw_source, contract_name)

        # Plain single-file source
        return [self._make_contract(f"{contract_name}.sol", raw_source, "local")]

    def _from_sourcify(self) -> List[ContractFile]:
        chain_id = SUPPORTED_CHAINS[self.chain]["chain_id"]
        url = f"{_SOURCIFY_BASE}/{chain_id}/{self.address}"

        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        contracts: List[ContractFile] = []
        for file_info in data.get("files", []):
            name: str = file_info.get("name", "")
            content: str = file_info.get("content", "")
            path: str = file_info.get("path", name)

            if name.endswith(".sol") or name.endswith(".vy"):
                contracts.append(self._make_contract(name, content, path))

        return contracts

    def _parse_standard_json(self, source_json: str, contract_name: str) -> List[ContractFile]:
        try:
            data = json.loads(source_json)
        except json.JSONDecodeError:
            return []

        sources: dict = data.get("sources", {})
        contracts: List[ContractFile] = []

        for file_path, file_data in sources.items():
            content: str = file_data.get("content", "")
            if not content:
                continue
            name = file_path.split("/")[-1]
            contracts.append(self._make_contract(name, content, file_path))

        return contracts

    @staticmethod
    def _make_contract(name: str, content: str, path: str) -> ContractFile:
        language = "vyper" if name.endswith(".vy") else "solidity"
        return ContractFile(
            path=path,
            name=name,
            content=content,
            language=language,
            source="chain",
        )
