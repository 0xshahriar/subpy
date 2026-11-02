# SPDX-License-Identifier: MIT
# Developer task runner for subpy.
# Everything is invoked as `python3 -m <tool>` so targets work with or without
# an activated virtualenv (set PYTHON=... to override the interpreter).
# Usage: make <target>

PYTHON ?= python3
PKG     := subpy
EXTRAS  := dev

.DEFAULT_GOAL := help

# Declare all targets phony so a file named e.g. "build/" never shadows them.
.PHONY: help install dev test lint fmt typecheck build clean smoke all

help: ## Show this help
	@echo "subpy — available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-11s\033[0m %s\n", $$1, $$2}'

install: ## Install the package (no dev tooling)
	$(PYTHON) -m pip install .

dev: ## Editable install with the dev extra (ruff, mypy, pytest, build, twine)
	$(PYTHON) -m pip install -e ".[$(EXTRAS)]"

test: ## Run the test suite
	$(PYTHON) -m pytest

lint: ## Lint with ruff (no autofix)
	$(PYTHON) -m ruff check $(PKG)

fmt: ## Auto-fix and format with ruff
	$(PYTHON) -m ruff check --fix $(PKG)
	$(PYTHON) -m ruff format $(PKG)

typecheck: ## Static type check with mypy
	$(PYTHON) -m mypy

build: clean ## Build sdist + wheel and validate metadata
	$(PYTHON) -m build
	$(PYTHON) -m twine check dist/*

smoke: ## Offline CLI smoke test (no network, no DNS)
	$(PYTHON) -m $(PKG) --version
	$(PYTHON) -m $(PKG) --help

clean: ## Remove build artifacts and tool caches
	rm -rf build dist *.egg-info .eggs
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.py[cod]' -delete 2>/dev/null || true

all: fmt lint typecheck test smoke ## Format, lint, type-check, test, smoke
