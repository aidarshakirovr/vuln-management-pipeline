PYTHON ?= python3

.DEFAULT_GOAL := help

.PHONY: help install lint test demo defectdojo

help:
	@printf '%s\n' \
		'make install     install vmp and dev tools' \
		'make lint        ruff check and format check' \
		'make test        pytest' \
		'make demo        offline report from samples/ (no network)' \
		'make defectdojo  start local DefectDojo (requires a filled-in .env)'

install:
	$(PYTHON) -m pip install -e '.[dev]'

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

test:
	$(PYTHON) -m pytest

demo:
	$(PYTHON) -m vmp ingest samples/trivy.json samples/zap.json samples/nuclei.jsonl \
		--offline --cache-dir samples/cache --exposure internet --out-dir out/demo

defectdojo:
	@test -f .env || { echo 'Copy .env.example to .env and replace the placeholders.'; exit 1; }
	@if grep -q 'change-me' .env; then \
		echo '.env still contains change-me placeholders.'; \
		exit 1; \
	fi
	docker compose up -d
