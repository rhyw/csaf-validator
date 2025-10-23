.PHONY: install test

install:
	@uv pip install -e .

test: install
	@uv run pytest

CSAF_SAMPLE_FILES := $(wildcard csaf_validator/samples/*.json)

validate: install
	@echo "Validating CSAF sample files..."
	@for file in $(CSAF_SAMPLE_FILES); do \
		echo "Running validator on $$file..."; \
		uv run csaf-validator $$file || exit 1; \
	done
