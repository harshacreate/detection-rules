"""A deliberately small equality-only matcher for the sample Sigma rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


class RuleFormatError(ValueError):
    """Raised when an input rule or event uses an unsupported shape."""


def load_rules(directory: Path) -> list[dict[str, Any]]:
    if not directory.is_dir():
        raise RuleFormatError(f"rules directory does not exist: {directory}")
    rules = []
    for path in sorted(directory.glob("*.yml")):
        with path.open(encoding="utf-8") as handle:
            rule = yaml.safe_load(handle)
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            raise RuleFormatError(f"{path} must be a rule mapping with a string id")
        detection = rule.get("detection")
        if not isinstance(detection, dict) or not isinstance(detection.get("selection"), dict):
            raise RuleFormatError(f"{path} must define a mapping named detection.selection")
        if detection.get("condition") != "selection":
            raise RuleFormatError(f"{path} uses a condition outside the supported subset")
        if not all(isinstance(k, str) and isinstance(v, (str, int, float, bool))
                   for k, v in detection["selection"].items()):
            raise RuleFormatError(f"{path} selectors must be scalar equality pairs")
        rules.append(rule)
    if not rules:
        raise RuleFormatError(f"no .yml rules found in {directory}")
    return rules


def read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON on line {line_number}: {exc.msg}") from exc
            if not isinstance(event, dict) or not isinstance(event.get("event_id"), str):
                raise ValueError(f"line {line_number} must be a JSON object with string event_id")
            events.append(event)
    return events


def match_event(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    selection = rule["detection"]["selection"]
    return all(event.get(field) == expected for field, expected in selection.items())
