from pathlib import Path

import pytest


@pytest.fixture
def data_path():
    return Path(__file__).parent.parent / "csaf_validator" / "samples"


@pytest.fixture
def schema_path():
    return Path(__file__).parent.parent / "csaf_validator" / "schemas" / "csaf_2.0.json"
