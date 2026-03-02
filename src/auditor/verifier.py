import shutil
import tempfile
import subprocess
from pathlib import Path
from typing import Tuple, Dict


class DynamicVerifier:
    """
    Creates an isolated Foundry environment to test LLM-generated exploits
    against the target smart contracts to prove/disprove Slither findings.
    """

    def __init__(self):
        self._temp_dir = None
        self._forge_bin = shutil.which("forge")
        if not self._forge_bin:
            raise FileNotFoundError("Foundry tool 'forge' is not installed or not in PATH.")

    def _setup_isolated_env(
        self, target_contracts: Dict[str, str], poc_content: str
    ) -> Tuple[bool, str]:
        """
        1. Create temp dir
        2. forge init --force --no-commit
        3. Write vulnerable contracts to src/
        4. Write exploit test to test/

        Returns:
            (success, output) — output is always the raw stdout+stderr from forge init.
            Never raises; failures are communicated via the bool flag.
        """
        self._temp_dir = tempfile.mkdtemp(prefix="vigil_verify_")
        output = ""

        # Initialize Forge project
        init_cmd = [self._forge_bin, "init", "--force", "--no-commit"]
        try:
            result = subprocess.run(
                init_cmd,
                cwd=self._temp_dir,
                capture_output=True,
                text=True,
                timeout=120,
            )
            output = result.stdout + "\n" + result.stderr
            if result.returncode != 0:
                return False, f"[forge init failed]\n{output}"
        except subprocess.TimeoutExpired as e:
            out = (e.stdout or "").strip()
            err = (e.stderr or "").strip()
            return False, f"[forge init timed out]\n{out}\n{err}".strip()
        except Exception as e:
            return False, f"[forge init error] {e}\n{output}".strip()

        # Remove default boilerplate contracts
        forge_src = Path(self._temp_dir) / "src"
        forge_test = Path(self._temp_dir) / "test"

        for f in forge_src.glob("*.sol"):
            f.unlink()
        for f in forge_test.glob("*.sol"):
            f.unlink()

        # Write target contracts into src/
        for file_name, content in target_contracts.items():
            dest = forge_src / file_name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")

        # Write the LLM-generated exploit into test/
        poc_dest = forge_test / "Exploit.t.sol"
        poc_dest.write_text(poc_content, encoding="utf-8")

        return True, output

    def verify(self, target_contracts: Dict[str, str], poc_content: str) -> Tuple[bool, str]:
        """
        Runs the generated PoC in an isolated Foundry environment.

        Returns:
            - is_verified (bool): True if the exploit test passes (real vulnerability),
                                  False if it fails/reverts (false positive or unexploitable).
            - log (str): Full raw stdout+stderr from forge init and forge test,
                         always populated even on errors or timeouts.
        """
        output = ""
        try:
            # --- Phase 1: environment setup ---
            init_ok, init_output = self._setup_isolated_env(target_contracts, poc_content)
            output = init_output

            if not init_ok:
                return False, output

            # --- Phase 2: run forge test ---
            test_cmd = [self._forge_bin, "test", "-vvv"]
            try:
                result = subprocess.run(
                    test_cmd,
                    cwd=self._temp_dir,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                test_output = result.stdout + "\n" + result.stderr
                output += "\n" + test_output

                # A finding is a true positive only when every test passes and none fail
                if "[PASS]" in test_output and "[FAIL]" not in test_output:
                    return True, output

                return False, output

            except subprocess.TimeoutExpired as e:
                out = (e.stdout or "").strip()
                err = (e.stderr or "").strip()
                output += f"\n[forge test timed out]\n{out}\n{err}"
                return False, output

        except Exception as e:
            output += f"\n[Verification Error] {e}"
            return False, output
        finally:
            self._cleanup()

    def _cleanup(self):
        if self._temp_dir and Path(self._temp_dir).exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None
