.PHONY: test rules

test:
	python -m pytest

rules:
	python -m rulelab.cli samples/events.jsonl
