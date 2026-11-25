"""Rule engine for the baseline: decide BLOCK / THROTTLE / ALLOW from the SNI."""
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

import yaml

BLOCK, THROTTLE, ALLOW = "BLOCK", "THROTTLE", "ALLOW"


class RuleEngine:
    def __init__(self, default_action: str = ALLOW,
                 rules: Optional[Dict[str, str]] = None) -> None:
        self.default_action = default_action.upper()
        # domain -> action
        self.rules: Dict[str, str] = {
            d.lower().strip("."): a.upper() for d, a in (rules or {}).items()}

    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> "RuleEngine":
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        rules: Dict[str, str] = {}
        for entry in cfg.get("rules", []):
            for domain in entry.get("domains", []):
                rules[domain] = entry["action"]
        return cls(cfg.get("default_action", ALLOW), rules)

    def match(self, sni: Optional[str]) -> Tuple[str, str]:
        """Return (action, matched_rule). Longer (more specific) rules win."""
        if not sni:
            return self.default_action, ""
        host = sni.lower().strip(".")
        best = ""
        for domain in self.rules:
            if host == domain or host.endswith("." + domain):
                if len(domain) > len(best):
                    best = domain
        if best:
            return self.rules[best], best
        return self.default_action, ""
