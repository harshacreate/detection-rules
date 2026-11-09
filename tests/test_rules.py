import json
import subprocess
import sys
from pathlib import Path

import pytest
import yara

from rulelab.matcher import RuleFormatError, load_rules, match_event, read_events


ROOT = Path(__file__).resolve().parents[1]
SIGMA = ROOT / "rules" / "sigma"
YARA_DIR = ROOT / "rules" / "yara"


def test_sigma_positive_and_negative_controls():
    rules = load_rules(SIGMA)
    events = read_events(ROOT / "samples" / "events.jsonl")
    matched = {(event["event_id"], rule["id"])
               for event in events for rule in rules if match_event(rule, event)}
    assert len(rules) == 3
    assert len(matched) == 3
    assert not any(event_id == "evt-004" for event_id, _ in matched)


def test_event_validation_rejects_missing_event_id(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text(json.dumps({"event_name": "ConsoleLogin"}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="event_id"):
        read_events(path)


def test_event_validation_rejects_malformed_json(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        read_events(path)


def test_rule_loader_rejects_unsupported_condition(tmp_path):
    (tmp_path / "unsupported.yml").write_text(
        "id: test\ndetection:\n  selection: {event_name: test}\n  condition: selection or other\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleFormatError, match="outside the supported subset"):
        load_rules(tmp_path)


@pytest.mark.parametrize(
    ("rule_file", "positive", "negative"),
    [
        ("suspicious_powershell_strings.yar", "powershell.txt", "powershell.txt"),
        ("credential_file_reference.yar", "credential_path.txt", "credential_path.txt"),
    ],
)
def test_yara_positive_and_negative_fixtures(rule_file, positive, negative):
    rule = yara.compile(filepath=str(YARA_DIR / rule_file))
    positive_path = ROOT / "samples" / "yara" / "positive" / positive
    negative_path = ROOT / "samples" / "yara" / "negative" / negative
    assert rule.match(str(positive_path))
    assert not rule.match(str(negative_path))


def test_cli_runs_and_emits_expected_matches():
    result = subprocess.run(
        [sys.executable, "-m", "rulelab.cli", "samples/events.jsonl"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    assert len(result.stdout.splitlines()) == 3
    assert '"event_id": "evt-001"' in result.stdout
