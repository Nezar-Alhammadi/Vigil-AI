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


# يقبل الروابط بصيغة: https://github.com/owner/repo
_GITHUB_PATTERN = re.compile(
    r"^https?://github\.com/[\w\-\.]+/[\w\-\.]+(\.git)?(/.*)?$",
    re.IGNORECASE,
)


class GitHubLoader:
    """يقوم بنسخ مستودع GitHub واستخراج ملفات العقود الذكية."""

    def __init__(self, url: str):
        self.original_url = url.strip()
        # بناء رابط النسخ النظيف (ينتهي دائماً بـ .git)
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

            # --- الإصلاح البرمجي لمشكلة مكتبات Foundry ---
            if self._temp_dir:
                root_path = Path(self._temp_dir)
                # التحقق مما إذا كان المشروع يعتمد على إطار عمل Foundry
                if (root_path / "foundry.toml").exists():
                    forge_bin = shutil.which("forge")
                    if forge_bin:
                        # تشغيل أمر تثبيت المكتبات (dependencies) داخل المجلد المؤقت
                        subprocess.run(
                            [forge_bin, "install"],
                            cwd=self._temp_dir,
                            capture_output=True,
                            text=True,
                            timeout=300
                        )
            # ---------------------------------------------

            loader = LocalLoader(self._temp_dir)
            contracts = loader.load()
            
            # إعادة وسم المصدر ليعرف المستدعي أن هذه الملفات من GitHub
            for c in contracts:
                c.source = "github"
                # جعل المسار نسبياً ليكون الإخراج أنظف
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
        """المسار المؤقت للمستودع المنسوخ."""
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