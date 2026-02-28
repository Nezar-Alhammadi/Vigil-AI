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
    """يقوم بنسخ مستودع GitHub واستخراج ملفات العقود الذكية مع تثبيت التبعيات."""

    def __init__(self, url: str):
        self.original_url = url.strip()
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
            self._install_dependencies()

            loader = LocalLoader(self._temp_dir)
            contracts = loader.load()
            
            resolved_temp = Path(self._temp_dir).resolve()
            
            for c in contracts:
                c.source = "github"
                c.path = str(Path(c.path).relative_to(resolved_temp))
            
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
        return self._temp_dir

    def _clone(self) -> None:
        result = subprocess.run(
            [
                "git",
                "clone",
                "--recurse-submodules",
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

    def _install_dependencies(self) -> None:
        """محاولة تهيئة المشروع بالكامل وتثبيت جميع المكتبات قبل الفحص."""
        if not self._temp_dir:
            return

        root = Path(self._temp_dir)
        lib_dir = root / "lib"
        lib_dir.mkdir(exist_ok=True)

        # 0. إصلاح مشكلة روابط SSH في الـ gitmodules والتي تمنع التحميل السليم
        gitmodules_path = root / ".gitmodules"
        if gitmodules_path.exists():
            content = gitmodules_path.read_text(errors="ignore")
            # تحويل SSH إلى HTTPS لضمان نجاح التنزيل
            content = re.sub(r"git@github\.com:", "https://github.com/", content)
            content = re.sub(r"ssh://git@github\.com/", "https://github.com/", content)
            gitmodules_path.write_text(content)
            # مزامنة الروابط الجديدة
            subprocess.run(["git", "submodule", "sync"], cwd=self._temp_dir, capture_output=True)

        # 1. تهيئة وتحديث الـ Submodules الخاصة بـ Git
        subprocess.run(
            ["git", "submodule", "update", "--init", "--recursive"],
            cwd=self._temp_dir,
            capture_output=True,
            timeout=60
        )

        # 2. تشغيل Makefile إذا وجد
        if (root / "Makefile").exists():
            subprocess.run(["make"], cwd=self._temp_dir, capture_output=True, timeout=120)

        # 3. تثبيت مكتبات Node.js إذا لزم الأمر
        if (root / "package.json").exists():
            if shutil.which("yarn"):
                subprocess.run(["yarn", "install"], cwd=self._temp_dir, capture_output=True, timeout=120)
            elif shutil.which("npm"):
                subprocess.run(["npm", "install", "--legacy-peer-deps"], cwd=self._temp_dir, capture_output=True, timeout=120)

        # 4. المُحلل الذكي للاعتماديات (Smart Dependency Resolver) - واعي بالإصدارات!
        needed_libs = set()
        sol_files = list(root.rglob("*.sol"))
        
        # اكتشاف إصدار Solidity لتحديد الفرع الصحيح لمكتبة OpenZeppelin
        solc_version = "0.8" 
        for sol_file in sol_files:
            try:
                content = sol_file.read_text(errors="ignore")
                if "pragma solidity ^0.7" in content or "pragma solidity 0.7" in content:
                    solc_version = "0.7"
                elif "pragma solidity ^0.6" in content or "pragma solidity 0.6" in content:
                    solc_version = "0.6"
                
                if "@openzeppelin" in content or "openzeppelin-contracts" in content: needed_libs.add("openzeppelin-contracts")
                if "forge-std" in content: needed_libs.add("forge-std")
                if "solmate" in content: needed_libs.add("solmate")
                if "base64" in content.lower(): needed_libs.add("base64")
                if "chainlink" in content.lower(): needed_libs.add("chainlink-brownie-contracts")
                if "solady" in content.lower(): needed_libs.add("solady")
            except Exception:
                pass
        
        # تحديد الفرع المناسب بناءً على إصدار Solidity الخاص بالمشروع
        oz_branch = "master"
        if solc_version == "0.7": 
            oz_branch = "v3.4.2-solc-0.7"
        elif solc_version == "0.6": 
            oz_branch = "v3.4.2"

        common_libs = {
            "openzeppelin-contracts": ("https://github.com/OpenZeppelin/openzeppelin-contracts.git", oz_branch),
            "forge-std": ("https://github.com/foundry-rs/forge-std.git", "master"),
            "solmate": ("https://github.com/transmissions11/solmate.git", "main"),
            "base64": ("https://github.com/Brechtpd/base64.git", "main"),
            "chainlink-brownie-contracts": ("https://github.com/smartcontractkit/chainlink-brownie-contracts.git", "main"),
            "solady": ("https://github.com/Vectorized/solady.git", "main")
        }
        
        # التنزيل المباشر كملفات (Brute-force Clone) للمكتبات المفقودة فقط
        for lib_name, (repo_url, branch) in common_libs.items():
            if lib_name in needed_libs:
                target_path = lib_dir / lib_name
                
                # نتحقق هل المجلد يحتوي فعلياً على ملفات العقود (.sol) لكي لا ننخدع بمجلدات فارغة
                has_sol_files = target_path.exists() and any(target_path.rglob("*.sol"))
                
                if not has_sol_files:
                    if target_path.exists():
                        shutil.rmtree(target_path, ignore_errors=True)
                    
                    subprocess.run(
                        ["git", "clone", "--depth", "1", "--branch", branch, repo_url, str(target_path)], 
                        capture_output=True, 
                        timeout=120
                    )

        # 5. تهيئة وبناء Foundry
        if (root / "foundry.toml").exists():
            forge_bin = shutil.which("forge")
            if forge_bin:
                subprocess.run(
                    [forge_bin, "build"], 
                    cwd=self._temp_dir, 
                    capture_output=True, 
                    timeout=120
                )

        # 6. تهيئة مشاريع Hardhat (إن وجدت)
        if (root / "hardhat.config.js").exists() or (root / "hardhat.config.ts").exists():
            npx_bin = shutil.which("npx")
            if npx_bin:
                subprocess.run(
                    [npx_bin, "hardhat", "compile"], 
                    cwd=self._temp_dir, 
                    capture_output=True, 
                    timeout=120
                )