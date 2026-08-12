import os
import yaml
from pathlib import Path
from typing import Dict, Any, List

class Config:
    def __init__(self, config_path: str = None):
        if config_path is None:
            # Look for rules.yaml in workspace root
            root_dir = Path(__file__).parent.parent
            config_path = root_dir / "rules.yaml"
            if not config_path.exists():
                config_path = Path("rules.yaml")

        self.config_path = Path(config_path)
        self.config_data = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            # Fallback to empty default config
            return {"enforce": True, "tools": {}}
        
        with open(self.config_path, "r", encoding="utf-8") as f:
            try:
                return yaml.safe_load(f) or {"enforce": True, "tools": {}}
            except Exception as e:
                print(f"Error reading config: {e}")
                return {"enforce": True, "tools": {}}

    @property
    def global_enforce(self) -> bool:
        return self.config_data.get("enforce", True)

    def get_tool_rules(self, tool_name: str) -> List[Dict[str, Any]]:
        self.config_data = self._load_config()
        tools = self.config_data.get("tools", {})
        return tools.get(tool_name, [])

# Singleton instance
config = Config()
