import os
import yaml
from pathlib import Path
from typing import Optional

class PoCGenerator:
    """
    Uses an LLM to generate a Foundry Proof of Concept (PoC) test file
    to dynamically verify a vulnerability found by Slither.
    """
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self._load_config()
        self._init_client()

    def _load_config(self):
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f) or {}
        except Exception as e:
            self.config = {}

        llm_config = self.config.get("llm", {})
        self.provider = llm_config.get("provider", "openai").lower()
        self.model = llm_config.get("model", "gpt-4-turbo")
        self.temperature = float(llm_config.get("temperature", 0.2))
        
        # Determine API Key from config or environment variables
        self.api_key = llm_config.get("api_key", "")
        if not self.api_key:
            if self.provider == "openai":
                self.api_key = os.getenv("OPENAI_API_KEY", "")
            elif self.provider == "openrouter":
                self.api_key = os.getenv("OPENROUTER_API_KEY", "")
            elif self.provider == "anthropic":
                self.api_key = os.getenv("ANTHROPIC_API_KEY", "")
            elif self.provider == "google":
                self.api_key = os.getenv("GEMINI_API_KEY", "")

        # If API key is still missing, interactively prompt the user
        if not self.api_key:
            import typer
            from rich.console import Console
            console = Console()
            
            console.print(f"\n[bold yellow]No API Key found for provider '{self.provider}'.[/bold yellow]")
            self.api_key = typer.prompt(f"Please enter your {self.provider.capitalize()} API Key", hide_input=True).strip()
            self.model = typer.prompt("Please enter the model you want to use", default=self.model).strip()
            
            # Update config dictionary
            if "llm" not in self.config:
                self.config["llm"] = {}
                
            self.config["llm"]["provider"] = self.provider
            self.config["llm"]["api_key"] = self.api_key
            self.config["llm"]["model"] = self.model
            
            # Save persistently to config.yaml
            try:
                with open(self.config_path, "w", encoding="utf-8") as f:
                    yaml.safe_dump(self.config, f, default_flow_style=False, sort_keys=False)
                console.print(f"[bold green]Successfully saved credentials to {self.config_path}.[/bold green]\n")
            except Exception as e:
                console.print(f"[bold red]Failed to save to {self.config_path}: {e}[/bold red]\n")

    def _init_client(self):
        if not self.api_key:
            raise ValueError(f"API key not found for provider '{self.provider}'. Setup config.yaml or env vars.")

        if self.provider == "openai":
            import openai
            self.client = openai.OpenAI(api_key=self.api_key)
        elif self.provider == "openrouter":
            import openai
            self.client = openai.OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=self.api_key
            )
        elif self.provider == "anthropic":
            import anthropic
            self.client = anthropic.Anthropic(api_key=self.api_key)
        elif self.provider == "google":
            from google import genai
            self.client = genai.Client(api_key=self.api_key)
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

    def generate_poc(self, contract_name: str, contract_content: str, vulnerability_desc: str) -> Optional[str]:
        """
        Sends the contract code and vulnerability description to the LLM
        and asks it to write a Foundry test (.t.sol) to exploit it.
        Returns the generated code.
        """
        prompt = f"""You are an Expert Web3 Security Engineer.
Slither has detected a vulnerability in the following smart contract. 
Your task is to write a standalone Foundry test (`Exploit.t.sol`) that successfully proves this vulnerability by executing an exploit.

### Contract Name:
{contract_name}

### Vulnerability Description (from Slither):
{vulnerability_desc}

### Vulnerability Verification Goal:
If the vulnerability is real, your Foundry test MUST FAIL or REVERT during the exploit execution, or it should include assertions that prove the exploit was successful (which we will interpret as a successful verification). 
Actually, standard convention: The test should contain a `testExploit()` function. If the vulnerability is real, the exploit should succeed, and `testExploit()` should PASS. If the vulnerability doesn't exist (false positive), `testExploit()` should FAIL/REVERT.

CRITICAL: You MUST use the EXACT SAME `pragma solidity` version as the provided target smart contract. Do not default to ^0.8.x if the contract is older. If the contract is <0.8.0, remember to import SafeMath if needed, but your primary goal is to make the test compile alongside the target.

### Target Smart Contract Source Code:
```solidity
{contract_content}
```

### Instructions:
1. Write a complete Foundry test contract named `ExploitTest` inheriting from `Test` (from `forge-std/Test.sol`).
2. Include the necessary setup in `setUp()` to deploy the contract.
3. Write a `test_ExtractedVulnerability()` function that performs the exploit.
4. Ensure all imports are correct (e.g., `import "forge-std/Test.sol";` and importing the vulnerable contract).
5. Output ONLY the raw Solidity code. No markdown formatting like ```solidity...```, just the code itself.
"""

        try:
            return self._call_llm(prompt)
        except Exception as e:
            print(f"[!] LLM Generation Error: {e}")
            return None

    def _call_llm(self, prompt: str) -> str:
        if self.provider in ["openai", "openrouter"]:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature
            )
            return self._clean_output(response.choices[0].message.content)

        elif self.provider == "anthropic":
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4000,
                temperature=self.temperature,
                messages=[{"role": "user", "content": prompt}]
            )
            return self._clean_output(response.content[0].text)

        elif self.provider == "google":
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config={"temperature": self.temperature}
            )
            return self._clean_output(response.text)

    def _clean_output(self, text: str) -> str:
        """Removes markdown code block backticks if the LLM hallucinated them."""
        text = text.strip()
        if text.startswith("```solidity"):
            text = text[len("```solidity"):].strip()
        elif text.startswith("```"):
            text = text[3:].strip()
            
        if text.endswith("```"):
            text = text[:-3].strip()
            
        return text
