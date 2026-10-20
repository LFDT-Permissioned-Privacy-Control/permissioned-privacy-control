# Demo Generator Makefile
#
# Usage:
#   make demo name=auth-flow        # Generate complete demo
#   make demo-record name=auth-flow # Record only
#   make demo-process name=auth-flow # Process existing recording
#   make demo-all                   # Generate all demos

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Directories
DEMOS_DIR := $(shell pwd)
PROJECT_ROOT := $(shell dirname $(DEMOS_DIR))
PLAYWRIGHT_DIR := $(DEMOS_DIR)/playwright
OUTPUT_DIR := $(DEMOS_DIR)/output
CONFIGS_DIR := $(DEMOS_DIR)/configs

# Python
PYTHON := python3
VENV := $(DEMOS_DIR)/.venv
PIP := $(VENV)/bin/pip
PYTHON_VENV := PYTHONPATH=$(PROJECT_ROOT) $(VENV)/bin/python

# Demo name (set via command line: make demo name=auth-flow)
name ?=

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: venv playwright-install ## Initial setup (run once)
	@echo "Setup complete!"

.PHONY: venv
venv: ## Create Python virtual environment
	@if [ ! -d "$(VENV)" ]; then \
		$(PYTHON) -m venv $(VENV); \
		$(PIP) install --upgrade pip; \
		$(PIP) install -r requirements.txt; \
		echo "Virtual environment created at $(VENV)"; \
	else \
		echo "Virtual environment already exists"; \
	fi

.PHONY: playwright-install
playwright-install: ## Install Playwright dependencies
	@cd $(PLAYWRIGHT_DIR) && npm install
	@cd $(PLAYWRIGHT_DIR) && npx playwright install chromium
	@echo "Playwright installed"

.PHONY: demo
demo: check-name ## Generate complete demo (name=<config_name>)
	@$(PYTHON_VENV) -m demos.cmd.demo-gen.main generate $(name)

.PHONY: demo-record
demo-record: check-name ## Record video only (name=<config_name>)
	@$(PYTHON_VENV) -m demos.cmd.demo-gen.main record $(name)

.PHONY: demo-process
demo-process: check-name ## Process existing recording (name=<config_name>)
	@$(PYTHON_VENV) -m demos.cmd.demo-gen.main process $(name)

.PHONY: demo-clip
demo-clip: ## Extract clips from video (video=<path>)
ifndef video
	$(error video is required. Usage: make demo-clip video=output/auth-flow/auth-flow.mp4)
endif
	@$(PYTHON_VENV) -m demos.cmd.demo-gen.main clip $(video)

.PHONY: demo-all
demo-all: ## Generate all demos
	@for config in $(CONFIGS_DIR)/*.yaml; do \
		name=$$(basename "$$config" .yaml); \
		echo "Generating demo: $$name"; \
		$(PYTHON_VENV) -m demos.cmd.demo-gen.main generate "$$name" || true; \
	done

.PHONY: demo-list
demo-list: ## List available demo configurations
	@$(PYTHON_VENV) -m demos.cmd.demo-gen.main list

.PHONY: clean
clean: ## Clean generated files
	@rm -rf $(OUTPUT_DIR)/*
	@rm -rf $(PLAYWRIGHT_DIR)/test-results
	@rm -rf $(DEMOS_DIR)/.cache
	@echo "Cleaned output directories"

.PHONY: clean-all
clean-all: clean ## Clean everything including venv
	@rm -rf $(VENV)
	@rm -rf $(PLAYWRIGHT_DIR)/node_modules
	@echo "Cleaned all generated files and dependencies"

.PHONY: check-name
check-name:
ifndef name
	$(error name is required. Usage: make demo name=auth-flow)
endif

# Development helpers
.PHONY: lint
lint: ## Run linting
	@$(VENV)/bin/ruff check src/ cmd/

.PHONY: format
format: ## Format code
	@$(VENV)/bin/ruff format src/ cmd/

.PHONY: test
test: ## Run tests
	@$(PYTHON_VENV) -m pytest tests/ -v
