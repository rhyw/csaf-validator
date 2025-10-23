"""Tests for the CSAF validator."""

import os

import pytest


def test_validator_initialization(validator):
    """Tests that the Validator class initializes correctly."""
    assert isinstance(validator.schema, dict)
    assert validator.schema  # Check that the schema is not empty


@pytest.mark.parametrize(
    "csaf_file, expected_valid",
    [
        ("cve-2016-3674.json", True),
    ],
)
def test_valid_csaf_files(validator, data_path, csaf_file, expected_valid):
    """Tests validation with various valid CSAF files."""
    file_path = os.path.join(data_path, csaf_file)
    result = validator.validate(file_path)
    assert (
        result.is_valid == expected_valid
    ), f"Validation failed for {csaf_file}: {result.errors}"


def test_invalid_csaf_file_missing_document_title(validator, data_path):
    """Tests validation with an invalid CSAF file (missing document title)."""
    invalid_doc = {"document": {"csaf_version": "2.0"}}
    invalid_file_path = os.path.join(data_path, "temp_invalid_missing_title.json")
    with open(invalid_file_path, "w") as f:
        import json

        json.dump(invalid_doc, f)

    result = validator.validate(invalid_file_path)
    assert not result.is_valid
    assert any(
        "is a required property" in err.message for err in result.errors
    ), "Expected error about missing document title not found."
    os.remove(invalid_file_path)


def test_invalid_csaf_file_wrong_csaf_version(validator, data_path):
    """Tests validation with an invalid CSAF file (wrong CSAF version)."""
    invalid_doc = {
        "document": {
            "csaf_version": "1.0",  # Incorrect version
            "title": "Test Advisory",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "tracking": {
                "id": "TEST-2023-0001",
                "status": "final",
                "version": "1.0.0",
                "initial_release_date": "2023-01-01T00:00:00Z",
                "current_release_date": "2023-01-01T00:00:00Z",
                "revision_history": [
                    {
                        "date": "2023-01-01T00:00:00Z",
                        "number": "1.0.0",
                        "summary": "Initial release",
                    }
                ],
            },
            "category": "csaf_security_advisory",
        }
    }
    invalid_file_path = os.path.join(data_path, "temp_invalid_wrong_version.json")
    with open(invalid_file_path, "w") as f:
        import json

        json.dump(invalid_doc, f)

    result = validator.validate(invalid_file_path)
    assert not result.is_valid
    assert any(
        "'1.0' is not one of ['2.0']" in err.message for err in result.errors
    ), "Expected error about wrong CSAF version not found."
    os.remove(invalid_file_path)
