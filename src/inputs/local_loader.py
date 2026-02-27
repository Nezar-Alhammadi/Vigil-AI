"""
Local Path Loader
-----------------
Scans a local directory or single file and returns all Solidity/Vyper contracts found.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple


SUPPORTED_EXTENSIONS = {".sol", ".vy"}
IGNORED_DIRS = {"node_modules", ".git", "lib", "artifacts", "cache", "out", "__pycache__"}


@dataclass
class ContractFile:
    """Represents a single smart contract source file."""
    path: str        # Absolute path on disk (or virtual path for on-chain contracts)
    name: str        # File name (e.g. Token.sol)
    content: str     # Raw source code
    language: str    # "solidity" or "vyper"
    source: str = "local"  # "local" | "github" | "chain"


class LocalLoader:
    """Loads smart contracts from a local file system path."""

    def __init__(self, path: str):
        self.root = Path(path).resolve()

    def validate(self) -> Tuple[bool, str]:
        if not self.root.exists():
            return False, f"Path does not exist: {self.root}"
        if self.root.is_file():
            if self.root.suffix.lower() not in SUPPORTED_EXTENSIONS:
                return False, (
                    f"File '{self.root.name}' is not a supported contract file. "
                    f"Expected: {', '.join(SUPPORTED_EXTENSIONS)}"
                )
        return True, ""

    def load(self) -> List[ContractFile]:
        if self.root.is_file():
            contract = self._read_file(self.root)
            return [contract] if contract else []

        contracts: List[ContractFile] = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            # Skip ignored directories in-place so os.walk doesn't descend into them
            dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
            for filename in filenames:
                file_path = Path(dirpath) / filename
                contract = self._read_file(file_path)
                if contract:
                    contracts.append(contract)

        return contracts

    def _read_file(self, file_path: Path) -> Optional[ContractFile]:
        suffix = file_path.suffix.lower()
        if suffix not in SUPPORTED_EXTENSIONS:
            return None

        language = "vyper" if suffix == ".vy" else "solidity"
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            return ContractFile(
                path=str(file_path),
                name=file_path.name,
                content=content,
                language=language,
                source="local",
            )
        except OSError:
            return None
