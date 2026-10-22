"""Knowledge base loader.

Loads and validates the versioned JSON/YAML rule files that drive every
analysis engine. All findings cite these rule IDs so reports stay traceable
to their source.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Optional

import yaml

_DEFAULT_KB_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "knowledgebase"
)
_DEFAULT_CONFIG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config"
)


class KnowledgeBaseError(RuntimeError):
    """Raised when a knowledge base file is missing or malformed."""


def _load_json(name: str, kb_dir: str) -> Any:
    path = os.path.join(kb_dir, name)
    if not os.path.isfile(path):
        raise KnowledgeBaseError(f"Knowledge base file missing: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError as exc:
            raise KnowledgeBaseError(f"{name} is not valid JSON: {exc}") from exc


def _load_yaml(name: str, cfg_dir: str) -> Any:
    path = os.path.join(cfg_dir, name)
    if not os.path.isfile(path):
        raise KnowledgeBaseError(f"Config file missing: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise KnowledgeBaseError(f"{name} is not valid YAML: {exc}") from exc


@dataclass
class KnowledgeBase:
    permissions: dict[str, Any]
    play_rules: dict[str, Any]
    owasp_rules: dict[str, Any]
    combinations: dict[str, Any]
    categories: dict[str, Any]
    appconfig: dict[str, Any]
    riskconfig: dict[str, Any]
    orgpolicy: dict[str, Any]
    errors: list[str] = field(default_factory=list)

    # convenience accessors -------------------------------------------------
    @property
    def permission_defs(self) -> dict[str, Any]:
        data = self.permissions
        if isinstance(data, dict) and "permissions" in data:
            return data["permissions"]
        return data if isinstance(data, dict) else {}

    @property
    def versions(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for label, doc in (
            ("android_permissions", self.permissions),
            ("google_play_rules", self.play_rules),
            ("owasp_rules", self.owasp_rules),
            ("suspicious_combinations", self.combinations),
            ("app_categories", self.categories),
            ("org_policy", self.orgpolicy),
        ):
            if isinstance(doc, dict):
                out[label] = str(doc.get("version", "unknown"))
        return out


@lru_cache(maxsize=4)
def load_knowledgebase(kb_dir: str = "", config_dir: str = "") -> KnowledgeBase:
    """Load (and cache) the full knowledge base."""
    kb_dir = kb_dir or _DEFAULT_KB_DIR
    config_dir = config_dir or _DEFAULT_CONFIG_DIR
    errors: list[str] = []

    def safe_json(name: str) -> Any:
        try:
            return _load_json(name, kb_dir)
        except KnowledgeBaseError as exc:
            errors.append(str(exc))
            return {}

    def safe_yaml(name: str) -> Any:
        try:
            return _load_yaml(name, config_dir)
        except KnowledgeBaseError as exc:
            errors.append(str(exc))
            return {}

    kb = KnowledgeBase(
        permissions=safe_json("androidpermissions.json"),
        play_rules=safe_json("googleplayrules.json"),
        owasp_rules=safe_json("owasprules.json"),
        combinations=safe_json("suspiciouscombinations.json"),
        categories=safe_json("appcategories.json"),
        appconfig=safe_yaml("appconfig.yaml"),
        riskconfig=safe_yaml("riskthresholds.yaml"),
        orgpolicy=safe_yaml("orgpolicy.yaml"),
        errors=errors,
    )
    return kb


def permission_entry(kb: KnowledgeBase, name: str) -> Optional[dict[str, Any]]:
    return kb.permission_defs.get(name)


def category_entry(kb: KnowledgeBase, category: str) -> Optional[dict[str, Any]]:
    if not category:
        return None
    cats = kb.categories.get("categories", kb.categories) if isinstance(kb.categories, dict) else {}
    if not isinstance(cats, dict):
        return None
    return cats.get(category.lower())


def all_categories(kb: KnowledgeBase) -> dict[str, Any]:
    if not isinstance(kb.categories, dict):
        return {}
    return kb.categories.get("categories", kb.categories)
