"""Core CSAF validation logic."""

import json

import jsonschema

from csaf_validator.rules import (
    ValidationError,
    check_mandatory_circular_definition_of_product_id,
    check_mandatory_contradicting_product_status,
    check_mandatory_missing_product_group_id_definition,
    check_mandatory_missing_product_id_definition,
    check_mandatory_multiple_definition_of_product_group_id,
    check_mandatory_multiple_product_id_definitions,
)


class ValidationResult:
    def __init__(self, is_valid, errors):
        self.is_valid = is_valid
        self.errors = errors


class Validator:
    """
    Handles CSAF validation against a specific schema version.
    """

    def __init__(self, schema_file_path):
        """
        Initializes the validator with a specific schema file path.

        Args:
            schema_file_path: Absolute path to the CSAF schema file.
        """
        with open(schema_file_path, "r") as f:
            self.schema = json.load(f)

    def validate(self, csaf_file):
        """
        Validates a CSAF file.

        Args:
            csaf_file: Path to the CSAF file.

        Returns:
            ValidationResult object.
        """
        with open(csaf_file, "r") as f:
            instance = json.load(f)
        errors = []
        try:
            jsonschema.validate(instance=instance, schema=self.schema)
        except jsonschema.exceptions.ValidationError as err:
            errors.append(ValidationError("SCHEMA_VALIDATION_ERROR", str(err)))

        # Run custom rules
        errors.extend(check_mandatory_missing_product_id_definition(instance))
        errors.extend(check_mandatory_multiple_product_id_definitions(instance))
        errors.extend(check_mandatory_circular_definition_of_product_id(instance))
        errors.extend(check_mandatory_missing_product_group_id_definition(instance))
        errors.extend(check_mandatory_multiple_definition_of_product_group_id(instance))
        errors.extend(check_mandatory_contradicting_product_status(instance))

        return ValidationResult(not bool(errors), errors)
