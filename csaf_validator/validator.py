"""Core CSAF validation logic."""

import json
import jsonschema
import os


class Validator:
    """Handles CSAF validation against a specific schema version."""

    def __init__(self, schema_version="2.0"):
        """
        Initializes the validator with a specific schema version.

        Args:
            schema_version: The CSAF schema version (e.g., "2.0").
        """
        self.schema_version = schema_version
        self.schema = self._load_schema()

    def _load_schema(self):
        """Loads the appropriate CSAF JSON schema."""
        schema_path = os.path.join(
            os.path.dirname(__file__), "schemas", f"csaf_{self.schema_version}.json"
        )
        with open(schema_path, "r") as f:
            return json.load(f)

    def validate(self, csaf_file):
        """
        Validates a CSAF file.

        Args:
            csaf_file: Path to the CSAF file.

        Returns:
            True if valid, False otherwise.
        """
        with open(csaf_file, "r") as f:
            instance = json.load(f)
        try:
            jsonschema.validate(instance=instance, schema=self.schema)
            return True
        except jsonschema.exceptions.ValidationError as err:
            print(f"Validation error: {err}")
            return False
