"""Core CSAF validation logic."""

import json

import jsonschema

from csaf_validator.rules import (
    ValidationError,
    check_mandatory_circular_definition_of_product_id,
    check_mandatory_contradicting_product_status,
    check_mandatory_cwe,
    check_mandatory_document_status_draft,
    check_mandatory_flag_without_product_reference,
    check_mandatory_inconsistent_cvss,
    check_mandatory_invalid_cvss,
    check_mandatory_invalid_cvss_computation,
    check_mandatory_language,
    check_mandatory_latest_document_version,
    check_mandatory_missing_item_in_revision_history,
    check_mandatory_missing_product_group_id_definition,
    check_mandatory_missing_product_id_definition,
    check_mandatory_multiple_definition_in_revision_history,
    check_mandatory_multiple_definition_of_product_group_id,
    check_mandatory_multiple_product_id_definitions,
    check_mandatory_multiple_scores_with_same_version_per_product,
    check_mandatory_multiple_use_of_same_cve,
    check_mandatory_non_draft_document_version,
    check_mandatory_prohibited_document_category_name,
    check_mandatory_purl,
    check_mandatory_released_revision_history,
    check_mandatory_revision_history_entries_for_pre_release_versions,
    check_mandatory_sorted_revision_history,
    check_mandatory_translator,
    check_mandatory_version_range_in_product_version,
)

_ALL_RULES = [
    check_mandatory_missing_product_id_definition,
    check_mandatory_multiple_product_id_definitions,
    check_mandatory_circular_definition_of_product_id,
    check_mandatory_missing_product_group_id_definition,
    check_mandatory_multiple_definition_of_product_group_id,
    check_mandatory_contradicting_product_status,
    check_mandatory_multiple_scores_with_same_version_per_product,
    check_mandatory_invalid_cvss,
    check_mandatory_invalid_cvss_computation,
    check_mandatory_inconsistent_cvss,
    check_mandatory_cwe,
    check_mandatory_language,
    check_mandatory_purl,
    check_mandatory_sorted_revision_history,
    check_mandatory_translator,
    check_mandatory_latest_document_version,
    check_mandatory_document_status_draft,
    check_mandatory_non_draft_document_version,
    check_mandatory_released_revision_history,
    check_mandatory_revision_history_entries_for_pre_release_versions,
    check_mandatory_missing_item_in_revision_history,
    check_mandatory_multiple_definition_in_revision_history,
    check_mandatory_multiple_use_of_same_cve,
    check_mandatory_prohibited_document_category_name,
    check_mandatory_version_range_in_product_version,
    check_mandatory_flag_without_product_reference,
]


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
        errors.extend(
            check_mandatory_multiple_scores_with_same_version_per_product(instance)
        )
        errors.extend(check_mandatory_invalid_cvss(instance))
        errors.extend(check_mandatory_invalid_cvss_computation(instance))
        errors.extend(check_mandatory_inconsistent_cvss(instance))
        errors.extend(check_mandatory_cwe(instance))
        errors.extend(check_mandatory_language(instance))
        errors.extend(check_mandatory_purl(instance))
        errors.extend(check_mandatory_sorted_revision_history(instance))
        errors.extend(check_mandatory_translator(instance))
        errors.extend(check_mandatory_latest_document_version(instance))
        errors.extend(check_mandatory_document_status_draft(instance))
        errors.extend(check_mandatory_non_draft_document_version(instance))
        errors.extend(check_mandatory_released_revision_history(instance))
        errors.extend(check_mandatory_multiple_definition_in_revision_history(instance))
        errors.extend(check_mandatory_multiple_use_of_same_cve(instance))
        errors.extend(check_mandatory_prohibited_document_category_name(instance))
        errors.extend(check_mandatory_version_range_in_product_version(instance))
        errors.extend(check_mandatory_flag_without_product_reference(instance))
        errors.extend(
            check_mandatory_revision_history_entries_for_pre_release_versions(instance)
        )
        errors.extend(check_mandatory_missing_item_in_revision_history(instance))

        return ValidationResult(not bool(errors), errors)
