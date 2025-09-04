"""Tests for the CSAF validator."""

import pytest
import os
from csaf_validator.validator import Validator


def test_validator_initialization():
    """Tests that the Validator class initializes correctly."""
    validator = Validator(schema_version="2.0")
    assert validator.schema_version == "2.0"
    assert isinstance(validator.schema, dict)
    assert validator.schema  # Check that the schema is not empty


def test_valid_csaf_file():
    """Tests validation with a valid CSAF file."""
    validator = Validator(schema_version="2.0")
    sample_file = os.path.join(
        os.path.dirname(__file__), "..", "csaf_validator", "samples", "cve-2016-3674.json"
    )
    assert validator.validate(sample_file) is True


def test_invalid_csaf_file():
    """Tests validation with an invalid CSAF file."""
    validator = Validator(schema_version="2.0")
    # Create a dummy invalid file for testing
    invalid_file = "invalid.json"
    with open(invalid_file, "w") as f:
        f.write('{"document": {"title": "Invalid CSAF file"}}')
    assert validator.validate(invalid_file) is False
    os.remove(invalid_file)
