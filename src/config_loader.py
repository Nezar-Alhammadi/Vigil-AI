"""
Vigil-AI Configuration Loader
-----------------------------
Safely reads config.yaml from the project root.
"""

from __future__ import annotations

import os
from pathlib import Path
import yaml

def load_config() -> dict:
    """Read config.yaml safely. Returns an empty dict if the file is missing or invalid."""
    config_path = Path("config.yaml").resolve()
    if not config_path.exists():
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            return config if isinstance(config, dict) else {}
    except Exception:
        return {}
