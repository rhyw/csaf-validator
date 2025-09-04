"""Tests for the CSAF validator."""

import pytest
from csaf_validator.validator import Validator


def test_validator_initialization():
    """Tests that the Validator class initializes correctly."""
    validator = Validator(schema_version="2.0")
    assert validator.schema_version == "2.0"
    assert isinstance(validator.schema, dict)


def test_validation_placeholder():
    """Placeholder test for the validation logic."""
    validator = Validator(schema_version="2.0")
    # TODO: Create a sample CSAF file for testing
    assert validator.validate("sample.json") is True
