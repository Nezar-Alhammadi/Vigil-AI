"""
GitHub Repository Loader
------------------------
Clones a GitHub repository into a temporary directory, extracts all contracts,
then cleans up automatically.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Tuple

from .local_loader import ContractFile, LocalLoader


# Accepts: https://github.com/owner/repo  (with or without .git, trailing slash, or sub-path)
_GITHUB_PATTERN = re.compile(
    r"^https?://github\.com/[\w\-\.]+/[\w\-\.]+(\.git)?(/.*)?$",
    re.IGNORECASE,
)


class GitHubLoader:
    """Clones a GitHub repository and extracts smart contract source files."""

    def __init__(self, url: str):
        self.original_url = url.strip()
        # Build the clean clone URL (always end with .git)
        base = self.original_url.split(".git")[0].rstrip("/")
        self._clone_url = base + ".git"
        self._temp_dir: str | None = None

    def validate(self) -> Tuple[bool, str]:
        if not _GITHUB_PATTERN.match(self.original_url):
            return False, (
                f"'{self.original_url}' is not a valid GitHub repository URL.\n"
                "  Expected format: https://github.com/<owner>/<repo>"
            )
        return True, ""

    def load(self) -> List[ContractFile]:
        self._temp_dir = tempfile.mkdtemp(prefix="vigil_github_")
        try:
            self._clone()
            loader = LocalLoader(self._temp_dir)
            contracts = loader.load()
            # Re-tag source so the caller knows these came from GitHub
            for c in contracts:
                c.source = "github"
                # Make path relative-looking for cleaner output
                c.path = str(Path(c.path).relative_to(self._temp_dir))
            return contracts
        except Exception:
            self.cleanup()
            raise

    def cleanup(self) -> None:
        if self._temp_dir and Path(self._temp_dir).exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None

    @property
    def repo_path(self) -> str | None:
        """Temporary cloned repository path while loaded."""
        return self._temp_dir

    # ------------------------------------------------------------------
    def _clone(self) -> None:
        result = subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--recurse-submodules",
                "--shallow-submodules",
                self._clone_url,
                self._temp_dir,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"git clone failed for '{self._clone_url}':\n{result.stderr.strip()}"
            )
