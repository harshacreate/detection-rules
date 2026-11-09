"""CLI for matching normalized JSONL events against the included Sigma subset."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, Optional

from .matcher import load_rules, match_event, read_events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, help="JSONL event file")
    parser.add_argument(
        "--rules",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "rules" / "sigma",
        help="directory containing the supported Sigma YAML subset",
    )
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    rules = load_rules(args.rules)
    for event in read_events(args.events):
        for rule in rules:
            if match_event(rule, event):
                print(json.dumps({"event_id": event["event_id"], "rule_id": rule["id"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
