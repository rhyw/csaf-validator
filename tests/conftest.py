import os
from pathlib import Path

import pytest

from csaf_validator.validator import Validator


@pytest.fixture(scope="session")
def csaf_schema_path():
    """
    Fixture that provides the absolute path to the CSAF 2.0 JSON schema.
    """
    return os.path.join(
        os.path.dirname(__file__),
        "..",
        "csaf_validator",
        "schemas",
        "csaf_2.0.json",
    )


@pytest.fixture(scope="session")
def validator(csaf_schema_path):
    """
    Fixture that provides a Validator instance initialized with the CSAF schema.
    """
    return Validator(schema_file_path=csaf_schema_path)


@pytest.fixture
def data_path():
    """
    Fixture that provides the path to the sample data directory.
    """
    return Path(os.path.dirname(__file__)) / ".." / "csaf_validator" / "samples"
