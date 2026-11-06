# >> COPYRIGHT-BEGIN <<
# ─────────────────────────────────────────────────────────────
#  © 2026 MAGUALINE 初创团队 · MAGUALINE 威胁流量防护台
#     项目:magualine-lite · 原始开发贡献者:包博文、孙敦龙、孙瑞晰、梁晨、段雅怡、刘羽纯、陈陆洋
#     本软件为专有软件(闭源),© 2026 MAGUALINE 初创团队 保留所有权利。
#     未经书面许可,不得分发、商用或移除本版权标记。
#     许可详见:PROPRIETARY-LICENSE.md · 署名详见:NOTICE.md
# ─────────────────────────────────────────────────────────────
# << COPYRIGHT-END >>
from __future__ import annotations

import json
import logging
from pathlib import Path

from .config import get_settings


LOGGER = logging.getLogger(__name__)
SKIPPED_RULE_FILE_SUFFIXES = (".example.json",)


def get_rules_directory() -> Path:
    return get_settings().rules_dir


def iter_rule_files(directory: Path | None = None) -> tuple[Path, ...]:
    rules_dir = Path(directory or get_rules_directory())
    if not rules_dir.exists():
        LOGGER.info("Rule directory does not exist: %s", rules_dir)
        return ()

    files = [
        path
        for path in sorted(rules_dir.glob("*.json"))
        if path.is_file() and not any(path.name.endswith(suffix) for suffix in SKIPPED_RULE_FILE_SUFFIXES)
    ]
    return tuple(files)


def _extract_rule_specs(payload: object, source_name: str) -> list[dict[str, object]]:
    if isinstance(payload, list):
        raw_rules = payload
        file_enabled = True
    elif isinstance(payload, dict):
        file_enabled = bool(payload.get("enabled", True))
        raw_rules = payload.get("rules", [])
    else:
        LOGGER.warning("Skipping rule file %s: top-level JSON must be an object or list", source_name)
        return []

    if not file_enabled:
        LOGGER.info("Rule file disabled by config: %s", source_name)
        return []

    if not isinstance(raw_rules, list):
        LOGGER.warning("Skipping rule file %s: 'rules' must be a list", source_name)
        return []

    specs: list[dict[str, object]] = []
    for index, item in enumerate(raw_rules, start=1):
        if not isinstance(item, dict):
            LOGGER.warning("Skipping rule %s#%s: item must be an object", source_name, index)
            continue
        if not bool(item.get("enabled", True)):
            continue

        spec = dict(item)
        spec.pop("enabled", None)
        spec.pop("comment", None)
        spec.setdefault("source_file", source_name)
        specs.append(spec)
    return specs


def load_json_rule_specs(directory: Path | None = None) -> tuple[dict[str, object], ...]:
    specs: list[dict[str, object]] = []
    seen_rule_ids: set[str] = set()

    for rule_file in iter_rule_files(directory):
        try:
            payload = json.loads(rule_file.read_text(encoding="utf-8"))
        except Exception as exc:
            LOGGER.warning("Failed to load rule file %s: %s", rule_file.name, exc)
            continue

        for spec in _extract_rule_specs(payload, rule_file.name):
            rule_id = str(spec.get("rule_id") or spec.get("id") or "").strip()
            if rule_id and rule_id in seen_rule_ids:
                LOGGER.warning("Skipping duplicate external rule_id '%s' from %s", rule_id, rule_file.name)
                continue
            if rule_id:
                seen_rule_ids.add(rule_id)
            specs.append(spec)

    return tuple(specs)
