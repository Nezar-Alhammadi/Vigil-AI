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
        # بناء رابط النسخ النظيف
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
            # 1. نسخ المستودع (بالكامل بدون نسخ سطحي)
            self._clone()

            # 2. تهيئة المشروع بالكامل وتثبيت التبعيات والمكتبات
            self._install_dependencies()

            # 3. تحميل الملفات باستخدام LocalLoader
            loader = LocalLoader(self._temp_dir)
            contracts = loader.load()
            
            # الحل: عمل resolve للمسار المؤقت قبل استخراج المسار النسبي لتجنب أخطاء الـ Symlinks
            resolved_temp = Path(self._temp_dir).resolve()
            
            # إعادة وسم المصدر ليعرف المستدعي أن هذه الملفات من GitHub
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
        """المسار المؤقت للمستودع المنسوخ."""
        return self._temp_dir

    def _clone(self) -> None:
        """عملية نسخ المستودع بالكامل مع الـ submodules."""
        # تمت إزالة --depth 1 و --shallow-submodules لضمان عمل Foundry و git بشكل سليم
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

        # 1. تهيئة وتحديث الـ Submodules الخاصة بـ Git إن وجدت
        subprocess.run(
            ["git", "submodule", "update", "--init", "--recursive"],
            cwd=self._temp_dir,
            capture_output=True,
            timeout=60
        )

        # 2. تشغيل Makefile إذا وجد (كثير من مستودعات مسابقات التدقيق تستخدمه لتحميل المكتبات)
        if (root / "Makefile").exists():
            subprocess.run(["make"], cwd=self._temp_dir, capture_output=True, timeout=120)

        # 3. تثبيت مكتبات Node.js إذا لزم الأمر
        if (root / "package.json").exists():
            if shutil.which("yarn"):
                subprocess.run(["yarn", "install"], cwd=self._temp_dir, capture_output=True, timeout=120)
            elif shutil.which("npm"):
                subprocess.run(["npm", "install", "--legacy-peer-deps"], cwd=self._temp_dir, capture_output=True, timeout=120)

        # 4. تهيئة مشاريع Foundry مع "المُحلل الذكي للاعتماديات الناقصة"
        if (root / "foundry.toml").exists():
            forge_bin = shutil.which("forge")
            if forge_bin:
                subprocess.run(
                    [forge_bin, "install", "--no-commit"], 
                    cwd=self._temp_dir, 
                    capture_output=True, 
                    timeout=120
                )
                
                # --- بداية المُحلل الذكي للاعتماديات (Smart Dependency Resolver) ---
                lib_dir = root / "lib"
                lib_dir.mkdir(exist_ok=True)
                
                # قاموس بأشهر المكتبات التي تنقص عادة في مشاريع مسابقات التدقيق
                common_libs = {
                    "openzeppelin-contracts": "OpenZeppelin/openzeppelin-contracts",
                    "forge-std": "foundry-rs/forge-std",
                    "solmate": "transmissions11/solmate",
                    "base64": "Brechtpd/base64",
                    "chainlink-brownie-contracts": "smartcontractkit/chainlink-brownie-contracts",
                    "foundry-devops": "Cyfrin/foundry-devops",
                    "solady": "Vectorized/solady"
                }
                
                # فحص ملفات الكود لمعرفة ما الذي استورده المبرمج حقاً
                needed_libs = set()
                for sol_file in root.rglob("*.sol"):
                    try:
                        content = sol_file.read_text(errors="ignore")
                        if "@openzeppelin" in content: needed_libs.add("openzeppelin-contracts")
                        if "forge-std" in content: needed_libs.add("forge-std")
                        if "solmate" in content: needed_libs.add("solmate")
                        if "base64" in content.lower(): needed_libs.add("base64")
                        if "chainlink" in content.lower(): needed_libs.add("chainlink-brownie-contracts")
                        if "solady" in content.lower(): needed_libs.add("solady")
                    except Exception:
                        pass
                
                # التثبيت الإجباري للمكتبات المطلوبة إذا لم تكن موجودة في مجلد lib
                for lib_name, repo_path in common_libs.items():
                    if lib_name in needed_libs and not (lib_dir / lib_name).exists():
                        subprocess.run(
                            [forge_bin, "install", repo_path, "--no-commit"], 
                            cwd=self._temp_dir, 
                            capture_output=True, 
                            timeout=120
                        )
                # --- نهاية المُحلل الذكي ---

                # عمل بناء (Build) صامت مسبقاً للتأكد من تحميل الـ remappings وتهيئة المشروع لـ Slither
                subprocess.run(
                    [forge_bin, "build"], 
                    cwd=self._temp_dir, 
                    capture_output=True, 
                    timeout=120
                )

        # 5. تهيئة مشاريع Hardhat (إن وجدت)
        if (root / "hardhat.config.js").exists() or (root / "hardhat.config.ts").exists():
            npx_bin = shutil.which("npx")
            if npx_bin:
                subprocess.run(
                    [npx_bin, "hardhat", "compile"], 
                    cwd=self._temp_dir, 
                    capture_output=True, 
                    timeout=120
                )