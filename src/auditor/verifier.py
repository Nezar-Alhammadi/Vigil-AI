import os
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

    def _setup_isolated_env(self, target_contracts: Dict[str, str], poc_content: str):
        """
        1. create temp dir
        2. forge init --no-commit
        3. write vulnerable contracts to src/
        4. write exploit test to test/
        """
        self._temp_dir = tempfile.mkdtemp(prefix="vigil_verify_")
        
        # Initialize Forge
        init_cmd = [self._forge_bin, "init", "--force", "--no-commit"]
        result = subprocess.run(
            init_cmd, 
            cwd=self._temp_dir, 
            capture_output=True, 
            text=True,
            timeout=120
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to initialize Foundry environment: {result.stderr}")
            
        # Clean default src/ and test/
        forge_src = Path(self._temp_dir) / "src"
        forge_test = Path(self._temp_dir) / "test"
        
        for f in forge_src.glob("*.sol"):
            f.unlink()
        for f in forge_test.glob("*.sol"):
            f.unlink()
            
        # Write Target Contracts
        for file_name, content in target_contracts.items():
            dest = forge_src / file_name
            # Ensure path exists for nested files
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
            
        # Write Exploit PoC
        poc_dest = forge_test / "Exploit.t.sol"
        poc_dest.write_text(poc_content, encoding="utf-8")

    def verify(self, target_contracts: Dict[str, str], poc_content: str) -> Tuple[bool, str]:
        """
        Runs the generated PoC in Foundry.
        Returns:
            - is_verified (bool): True if test passes (vulnerability is real), 
                                  False if fails/reverts (false positive)
            - log (str): `forge test` output for further inspection
        """
        try:
            self._setup_isolated_env(target_contracts, poc_content)
            
            # Run Forge Test
            test_cmd = [self._forge_bin, "test", "-vvv"]
            result = subprocess.run(
                test_cmd,
                cwd=self._temp_dir,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            output = result.stdout + "\n" + result.stderr
            
            # True Positive if the test passed
            if "[PASS]" in output and not "[FAIL]" in output:
                return True, output
                
            return False, output
            
        except subprocess.TimeoutExpired:
            return False, "Verification Timeout - PoC execution took too long."
        except Exception as e:
            return False, f"Verification Error: {str(e)}"
        finally:
            self._cleanup()

    def _cleanup(self):
        if self._temp_dir and Path(self._temp_dir).exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None
