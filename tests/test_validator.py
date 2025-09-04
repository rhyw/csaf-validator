"""Tests for the CSAF validator."""

import pytest
import os
from csaf_validator.validator import Validator

csaf_schema_path = os.path.join(os.path.dirname(__file__), "..", "csaf_validator", "schemas", "csaf_2.0.json")


def test_validator_initialization():
    """Tests that the Validator class initializes correctly."""
    csaf_schema_path = os.path.join(os.path.dirname(__file__), "..", "csaf_validator", "schemas", "csaf_2.0.json")
    validator = Validator(schema_file_path=csaf_schema_path)
    assert isinstance(validator.schema, dict)
    assert validator.schema  # Check that the schema is not empty


def test_valid_csaf_file():
    """Tests validation with a valid CSAF file."""
    validator = Validator(schema_file_path=csaf_schema_path)
    sample_file = os.path.join(
        os.path.dirname(__file__), "..", "csaf_validator", "samples", "cve-2016-3674.json"
    )
    assert validator.validate(sample_file).is_valid is True


def test_invalid_csaf_file():
    """Tests validation with an invalid CSAF file."""
    validator = Validator(schema_file_path=csaf_schema_path)
    # Create a dummy invalid file for testing
    invalid_file = "invalid.json"
    with open(invalid_file, "w") as f:
        f.write('{"document": {"title": "Invalid CSAF file"}}')
    assert validator.validate(invalid_file).is_valid is False
    os.remove(invalid_file)
