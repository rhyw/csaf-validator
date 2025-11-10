"Stub tests for CSAF 2.0 validation rules based on csaf-v2.0-os.md."

import copy
import json
import re

import pytest

from csaf_validator.rules import Rule, get_all_product_ids
from csaf_validator.validator import Validator


# Helper function to get all referenced product IDs
def _get_all_referenced_product_ids(doc):
    referenced_ids = set()
    if doc.get("product_tree"):
        for group in doc["product_tree"].get("product_groups", []):
            for product_id in group.get("product_ids", []):
                referenced_ids.add(product_id)
        for rel in doc["product_tree"].get("relationships", []):
            if "product_reference" in rel:
                referenced_ids.add(rel["product_reference"])
            if "relates_to_product_reference" in rel:
                referenced_ids.add(rel["relates_to_product_reference"])

    for vuln in doc.get("vulnerabilities", []):
        if "product_status" in vuln:
            for status_list in vuln["product_status"].values():
                for product_id in status_list:
                    referenced_ids.add(product_id)
        for remediation in vuln.get("remediations", []):
            for product_id in remediation.get("product_ids", []):
                referenced_ids.add(product_id)
        for score in vuln.get("scores", []):
            for product_id in score.get("products", []):
                referenced_ids.add(product_id)
        for threat in vuln.get("threats", []):
            for product_id in threat.get("product_ids", []):
                referenced_ids.add(product_id)
        for flag in vuln.get("flags", []):
            for product_id in flag.get("product_ids", []):
                referenced_ids.add(product_id)
    return referenced_ids


def test_mandatory_missing_product_id_definition(data_path, csaf_schema_path):
    """
    6.1.1 Missing Definition of Product ID
    For each element of type product_id_t that is not inside a
    full_product_name_t,
    it MUST be tested that the full_product_name_t element with the matching
    product_id exists.
    """
    csaf_file = data_path / "cve-2016-3674.json"
    with open(csaf_file, "r") as f:
        original_doc = json.load(f)

    # Get defined and referenced IDs before modification
    # defined_ids_before = get_all_product_ids(original_doc)
    # referenced_ids_before = _get_all_referenced_product_ids(original_doc)

    # Create a deep copy to modify
    doc = copy.deepcopy(original_doc)

    # Remove the definition of 'red_hat_bpm_suite_6'
    # This product_id is referenced in vulnerabilities.product_status.known_affected
    # and product_tree.relationships
    original_branches = doc["product_tree"]["branches"][0]["branches"]
    doc["product_tree"]["branches"][0]["branches"] = [
        branch
        for branch in original_branches
        if not (
            branch.get("product", {}).get("product_id") == "red_hat_bpm_suite_6"
            or (
                branch.get("category") == "product_family"
                and branch.get("name") == "Red Hat BPM Suite 6"
            )
        )
    ]

    # Get defined and referenced IDs after modification
    defined_ids_after = get_all_product_ids(doc)
    referenced_ids_after = _get_all_referenced_product_ids(doc)

    # Expected missing IDs are those referenced but not defined in the modified document
    expected_missing_ids = referenced_ids_after - defined_ids_after

    # Create a temporary file for the modified document
    temp_csaf_file = csaf_file.parent / "temp_cve-2016-3674_missing_product_id.json"
    with open(temp_csaf_file, "w") as f:
        json.dump(doc, f, indent=2)

    validator = Validator(csaf_schema_path)
    result = validator.validate(temp_csaf_file)

    assert not result.is_valid, "Validation was expected to fail but succeeded."

    actual_missing_ids = set()
    for err in result.errors:
        if err.rule == Rule.MANDATORY_MISSING_PRODUCT_ID_DEFINITION.name:
            match = re.search(
                r"Referenced product_id '([^']+)' is not defined in the product_tree.",
                err.message,
            )
            if match:
                actual_missing_ids.add(match.group(1))

    assert actual_missing_ids == expected_missing_ids, (
        f"Mismatch in missing product IDs.\nExpected: "
        f"{sorted(list(expected_missing_ids))}\nActual:   "
        f"{sorted(list(actual_missing_ids))}"
    )

    # Clean up the temporary file
    temp_csaf_file.unlink()


def test_mandatory_multiple_product_id_definitions(data_path, csaf_schema_path):
    """
    6.1.2 Multiple Definition of Product ID
    For each product_id_t in full_product_name_t elements, it MUST be tested
    that the product_id was not already defined within the same document.
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory",
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
        },
        "product_tree": {
            "full_product_names": [
                {"product_id": "CSAFPID-0001", "name": "Product A"},
                {"product_id": "CSAFPID-0002", "name": "Product B"},
            ],
            "branches": [
                {
                    "category": "vendor",
                    "name": "Vendor X",
                    "branches": [
                        {
                            "category": "product_name",
                            "name": "Product C",
                            "product": {
                                "product_id": "CSAFPID-0003",
                                "name": "Product C v1.0",
                            },
                        }
                    ],
                }
            ],
            "relationships": [
                {
                    "category": "installed_on",
                    "product_reference": "CSAFPID-0001",
                    "relates_to_product_reference": "CSAFPID-0002",
                    "full_product_name": {
                        "product_id": "CSAFPID-0004",
                        "name": "Product A on Product B",
                    },
                }
            ],
        },
    }

    validator = Validator(csaf_schema_path)
    doc1 = copy.deepcopy(base_csaf_doc)
    doc1["product_tree"]["full_product_names"].append(
        {"product_id": "CSAFPID-0001", "name": "Product A Duplicate"}
    )
    temp_file1 = data_path / "temp_multiple_product_id_full_product_names.json"
    with open(temp_file1, "w") as f:
        json.dump(doc1, f, indent=2)
    result1 = validator.validate(temp_file1)
    assert not result1.is_valid
    assert any(
        err.rule == Rule.MANDATORY_MULTIPLE_PRODUCT_ID_DEFINITIONS.name
        and "Product ID 'CSAFPID-0001' is defined multiple times in full_product_names."
        in err.message
        for err in result1.errors
    )
    temp_file1.unlink()

    # Test case 2: Duplicate in relationships
    doc2 = copy.deepcopy(base_csaf_doc)
    doc2["product_tree"]["relationships"].append(
        {
            "category": "installed_on",
            "product_reference": "CSAFPID-0001",
            "relates_to_product_reference": "CSAFPID-0002",
            "full_product_name": {
                "product_id": "CSAFPID-0004",
                "name": "Product A on Product B Duplicate",
            },
        }
    )
    temp_file2 = data_path / "temp_multiple_product_id_relationships.json"
    with open(temp_file2, "w") as f:
        json.dump(doc2, f, indent=2)
    result2 = validator.validate(temp_file2)
    assert not result2.is_valid
    assert any(
        err.rule == Rule.MANDATORY_MULTIPLE_PRODUCT_ID_DEFINITIONS.name
        and "Product ID 'CSAFPID-0004' is defined multiple times in relationships."
        in err.message
        for err in result2.errors
    )
    temp_file2.unlink()

    # Test case 3: Duplicate in branches
    doc3 = copy.deepcopy(base_csaf_doc)
    doc3["product_tree"]["branches"][0]["branches"].append(
        {
            "category": "product_name",
            "name": "Product C Duplicate",
            "product": {
                "product_id": "CSAFPID-0003",
                "name": "Product C v1.0 Duplicate",
            },
        }
    )
    temp_file3 = data_path / "temp_multiple_product_id_branches.json"
    with open(temp_file3, "w") as f:
        json.dump(doc3, f, indent=2)
    result3 = validator.validate(temp_file3)
    assert not result3.is_valid
    assert any(
        err.rule == Rule.MANDATORY_MULTIPLE_PRODUCT_ID_DEFINITIONS.name
        and "Product ID 'CSAFPID-0003' is defined multiple times in product_tree.branches."
        in err.message
        for err in result3.errors
    )
    temp_file3.unlink()

    # Test case 4: Duplicate across different sections (e.g., full_product_names and branches)
    doc4 = copy.deepcopy(base_csaf_doc)
    doc4["product_tree"]["full_product_names"].append(
        {
            "product_id": "CSAFPID-0003",  # Duplicate of product_id in branches
            "name": "Product C from Full Product Names",
        }
    )
    temp_file4 = data_path / "temp_multiple_product_id_cross_sections.json"
    with open(temp_file4, "w") as f:
        json.dump(doc4, f, indent=2)
    result4 = validator.validate(temp_file4)
    assert not result4.is_valid
    assert any(
        err.rule == Rule.MANDATORY_MULTIPLE_PRODUCT_ID_DEFINITIONS.name
        and "Product ID 'CSAFPID-0003' is defined multiple times in product_tree.branches."
        in err.message
        for err in result4.errors
    )
    temp_file4.unlink()

    # Test case 5: Valid document (no duplicates)
    temp_file5 = data_path / "temp_multiple_product_id_valid.json"
    with open(temp_file5, "w") as f:
        json.dump(base_csaf_doc, f, indent=2)
    result5 = validator.validate(temp_file5)
    assert result5.is_valid
    temp_file5.unlink()


def test_mandatory_circular_product_id_definition(data_path, csaf_schema_path):
    """
    6.1.3 Circular Definition of Product ID
    For each new defined product_id_t in items of relationships, it MUST be
    tested that the product_id does not end up in a circle.
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory",
            "tracking": {
                "id": "TEST-2023-0002",
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
            "category": "csaf_base",
        },
        "product_tree": {
            "full_product_names": [
                {"product_id": "CSAFPID-0001", "name": "Product A"},
                {"product_id": "CSAFPID-0002", "name": "Product B"},
            ],
            "relationships": [],
        },
    }

    validator = Validator(csaf_schema_path)

    # Test case 1: Direct circular dependency
    doc1 = copy.deepcopy(base_csaf_doc)
    doc1["product_tree"]["relationships"].append(
        {
            "category": "installed_on",
            "full_product_name": {
                "name": "Product C",
                "product_id": "CSAFPID-0003",
            },
            "product_reference": "CSAFPID-0001",
            "relates_to_product_reference": "CSAFPID-0003",  # Refers to itself
        }
    )
    temp_file1 = data_path / "temp_circular_direct.json"
    with open(temp_file1, "w") as f:
        json.dump(doc1, f, indent=2)
    result1 = validator.validate(temp_file1)
    assert not result1.is_valid
    assert any(
        err.rule == Rule.MANDATORY_CIRCULAR_DEFINITION_OF_PRODUCT_ID.name
        and "Circular dependency detected for product_id 'CSAFPID-0003'" in err.message
        for err in result1.errors
    )
    temp_file1.unlink()

    # Test case 2: Indirect circular dependency (A -> B -> A)
    doc2 = copy.deepcopy(base_csaf_doc)
    doc2["product_tree"]["relationships"].extend(
        [
            {
                "category": "installed_on",
                "full_product_name": {
                    "name": "Product C",
                    "product_id": "CSAFPID-0003",
                },
                "product_reference": "CSAFPID-0004",
                "relates_to_product_reference": "CSAFPID-0001",
            },
            {
                "category": "installed_on",
                "full_product_name": {
                    "name": "Product D",
                    "product_id": "CSAFPID-0004",
                },
                "product_reference": "CSAFPID-0003",
                "relates_to_product_reference": "CSAFPID-0002",
            },
        ]
    )
    temp_file2 = data_path / "temp_circular_indirect.json"
    with open(temp_file2, "w") as f:
        json.dump(doc2, f, indent=2)
    result2 = validator.validate(temp_file2)
    assert not result2.is_valid
    assert any(
        err.rule == Rule.MANDATORY_CIRCULAR_DEFINITION_OF_PRODUCT_ID.name
        and (
            "Circular dependency detected for product_id 'CSAFPID-0003'" in err.message
            or "Circular dependency detected for product_id 'CSAFPID-0004'"
            in err.message
        )
        for err in result2.errors
    )
    temp_file2.unlink()

    # Test case 3: No circular dependency
    doc3 = copy.deepcopy(base_csaf_doc)
    doc3["product_tree"]["relationships"].extend(
        [
            {
                "category": "installed_on",
                "full_product_name": {
                    "name": "Product C",
                    "product_id": "CSAFPID-0003",
                },
                "product_reference": "CSAFPID-0001",
                "relates_to_product_reference": "CSAFPID-0002",
            },
            {
                "category": "installed_on",
                "full_product_name": {
                    "name": "Product D",
                    "product_id": "CSAFPID-0004",
                },
                "product_reference": "CSAFPID-0003",
                "relates_to_product_reference": "CSAFPID-0001",
            },
        ]
    )
    temp_file3 = data_path / "temp_no_circular.json"
    with open(temp_file3, "w") as f:
        json.dump(doc3, f, indent=2)
    result3 = validator.validate(temp_file3)
    assert result3.is_valid
    temp_file3.unlink()


def test_mandatory_multiple_definition_of_product_group_id(data_path, csaf_schema_path):
    """
    6.1.5 Multiple Definition of Product Group ID
    For each Product Group ID (type /$defs/product_group_id_t) Product Group
    elements (/product_tree/product_groups[]) it MUST be tested that the
    group_id was not already defined within the same document.
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory",
            "tracking": {
                "id": "TEST-2023-0005",
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
            "category": "csaf_base",
        },
        "product_tree": {
            "full_product_names": [
                {"product_id": "CSAFPID-0001", "name": "Product A"},
                {"product_id": "CSAFPID-0002", "name": "Product B"},
                {"product_id": "CSAFPID-0003", "name": "Product C"},
            ],
            "product_groups": [
                {
                    "group_id": "CSAFGID-0001",
                    "product_ids": ["CSAFPID-0001", "CSAFPID-0002"],
                },
            ],
        },
    }

    validator = Validator(csaf_schema_path)

    # Test case 1: Duplicate Product Group ID definition
    doc1 = copy.deepcopy(base_csaf_doc)
    doc1["product_tree"]["product_groups"].append(
        {
            "group_id": "CSAFGID-0001",  # Duplicate
            "product_ids": ["CSAFPID-0001", "CSAFPID-0003"],
        }
    )
    temp_file1 = data_path / "temp_multiple_product_group_id_duplicate.json"
    with open(temp_file1, "w") as f:
        json.dump(doc1, f, indent=2)
    result1 = validator.validate(temp_file1)
    assert not result1.is_valid
    assert any(
        err.rule == Rule.MANDATORY_MULTIPLE_DEFINITION_OF_PRODUCT_GROUP_ID.name
        and (
            "Product Group ID 'CSAFGID-0001' is defined multiple times in "
            "product_tree.product_groups."
        )
        in err.message
        for err in result1.errors
    )
    temp_file1.unlink()

    # Test case 2: Valid document (no duplicate Product Group IDs)
    doc2 = copy.deepcopy(base_csaf_doc)
    doc2["product_tree"]["product_groups"].append(
        {
            "group_id": "CSAFGID-0002",
            "product_ids": ["CSAFPID-0001", "CSAFPID-0003"],
        }
    )
    temp_file2 = data_path / "temp_multiple_product_group_id_valid.json"
    with open(temp_file2, "w") as f:
        json.dump(doc2, f, indent=2)
    result2 = validator.validate(temp_file2)
    assert result2.is_valid
    temp_file2.unlink()


@pytest.mark.parametrize(
    "product_status_update, is_valid, error_message_part",
    [
        # Valid: No contradictions
        ({}, True, None),
        # Valid: Product in two lists of the same contradiction group
        (
            {"first_affected": ["CSAFPID-0001"]},
            True,
            None,
        ),
        # Valid: Product in 'affected' and 'recommended'
        (
            {"recommended": ["CSAFPID-0001"]},
            True,
            None,
        ),
        # Invalid: Affected vs. Not affected
        (
            {"known_not_affected": ["CSAFPID-0001"]},
            False,
            "is in both 'Affected' and 'Not Affected' status groups",
        ),
        # Invalid: Affected vs. Fixed
        (
            {"fixed": ["CSAFPID-0001"]},
            False,
            "is in both 'Affected' and 'Fixed' status groups",
        ),
        # Invalid: Affected vs. Under investigation
        (
            {"under_investigation": ["CSAFPID-0001"]},
            False,
            "is in both 'Affected' and 'Under Investigation' status groups",
        ),
        # Invalid: Not affected vs. Fixed
        (
            {
                "known_affected": [],
                "known_not_affected": ["CSAFPID-0003"],
                "fixed": ["CSAFPID-0003"],
            },
            False,
            "is in both 'Not Affected' and 'Fixed' status groups",
        ),
        # Invalid: Not affected vs. Under investigation
        (
            {
                "known_affected": [],
                "known_not_affected": ["CSAFPID-0004"],
                "under_investigation": ["CSAFPID-0004"],
            },
            False,
            "is in both 'Not Affected' and 'Under Investigation' status groups",
        ),
        # Invalid: Fixed vs. Under investigation
        (
            {
                "known_affected": [],
                "fixed": ["CSAFPID-0004"],
                "under_investigation": ["CSAFPID-0004"],
            },
            False,
            "is in both 'Fixed' and 'Under Investigation' status groups",
        ),
    ],
)
def test_mandatory_contradicting_product_status(
    product_status_update,
    is_valid,
    error_message_part,
    data_path,
    csaf_schema_path,
):
    """
    6.1.6 Contradicting Product Status
    For each item in /vulnerabilities it MUST be tested that the same Product ID
    is not member of contradicting product status groups.
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory",
            "tracking": {
                "id": "TEST-2023-0006",
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
            "category": "csaf_base",
        },
        "product_tree": {
            "full_product_names": [
                {"product_id": "CSAFPID-0001", "name": "Product A"},
                {"product_id": "CSAFPID-0002", "name": "Product B"},
                {"product_id": "CSAFPID-0003", "name": "Product C"},
                {"product_id": "CSAFPID-0004", "name": "Product D"},
            ],
        },
        "vulnerabilities": [
            {
                "title": "Vulnerability 1",
                "product_status": {
                    "known_affected": ["CSAFPID-0001"],
                    "known_not_affected": ["CSAFPID-0002"],
                    "fixed": ["CSAFPID-0003"],
                    "under_investigation": ["CSAFPID-0004"],
                },
            }
        ],
    }

    validator = Validator(csaf_schema_path)
    doc = copy.deepcopy(base_csaf_doc)
    doc["vulnerabilities"][0]["product_status"].update(product_status_update)

    temp_file = data_path / "temp_contradicting_product_status.json"
    with open(temp_file, "w") as f:
        json.dump(doc, f, indent=2)

    result = validator.validate(temp_file)

    if is_valid:
        assert result.is_valid
    else:
        assert not result.is_valid
        assert any(
            err.rule == Rule.MANDATORY_CONTRADICTING_PRODUCT_STATUS.name
            and error_message_part in err.message
            for err in result.errors
        )
    temp_file.unlink()


@pytest.mark.parametrize(
    "scores, is_valid, error_message_part",
    [
        # Valid: No duplicate scores for the same product and version
        (
            [
                {
                    "products": ["CSAFPID-0001"],
                    "cvss_v3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                    },
                },
                {
                    "products": ["CSAFPID-0002"],
                    "cvss_v3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        "baseScore": 5.3,
                        "baseSeverity": "MEDIUM",
                    },
                },
            ],
            True,
            None,
        ),
        # Valid: Same product, different CVSS versions
        (
            [
                {
                    "products": ["CSAFPID-0001"],
                    "cvss_v3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                    },
                },
                {
                    "products": ["CSAFPID-0001"],
                    "cvss_v2": {
                        "version": "2.0",
                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                        "baseScore": 5.0,
                    },
                },
            ],
            True,
            None,
        ),
        # Invalid: Same product, two CVSSv3.1 scores
        (
            [
                {
                    "products": ["CSAFPID-0001"],
                    "cvss_v3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                    },
                },
                {
                    "products": ["CSAFPID-0001"],
                    "cvss_v3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        "baseScore": 5.3,
                        "baseSeverity": "MEDIUM",
                    },
                },
            ],
            False,
            "Product ID 'CSAFPID-0001' has multiple scores for CVSS version 3.1",
        ),
        # Invalid: Same product, two CVSSv2 scores
        (
            [
                {
                    "products": ["CSAFPID-0001"],
                    "cvss_v2": {
                        "version": "2.0",
                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                        "baseScore": 5.0,
                    },
                },
                {
                    "products": ["CSAFPID-0001"],
                    "cvss_v2": {
                        "version": "2.0",
                        "vectorString": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
                        "baseScore": 4.3,
                    },
                },
            ],
            False,
            "Product ID 'CSAFPID-0001' has multiple scores for CVSS version 2.0",
        ),
        # Invalid: Product in a shared list with duplicate score version
        (
            [
                {
                    "products": ["CSAFPID-0001"],
                    "cvss_v3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                    },
                },
                {
                    "products": ["CSAFPID-0001", "CSAFPID-0002"],
                    "cvss_v3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        "baseScore": 5.3,
                        "baseSeverity": "MEDIUM",
                    },
                },
            ],
            False,
            "Product ID 'CSAFPID-0001' has multiple scores for CVSS version 3.1",
        ),
    ],
)
def test_mandatory_multiple_scores_with_same_version_per_product(
    scores, is_valid, error_message_part, data_path, csaf_schema_path
):
    """
    6.1.7 Multiple Scores with same Version per Product
    For each item in /vulnerabilities it MUST be tested that the same Product ID
    is not member of more than one CVSS-Vectors with the same version.
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory",
            "tracking": {
                "id": "TEST-2023-0007",
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
            "category": "csaf_base",
        },
        "product_tree": {
            "full_product_names": [
                {"product_id": "CSAFPID-0001", "name": "Product A"},
                {"product_id": "CSAFPID-0002", "name": "Product B"},
            ],
        },
        "vulnerabilities": [
            {
                "title": "Vulnerability 1",
                "scores": scores,
            }
        ],
    }

    validator = Validator(csaf_schema_path)
    doc = copy.deepcopy(base_csaf_doc)

    temp_file = data_path / "temp_multiple_scores.json"
    with open(temp_file, "w") as f:
        json.dump(doc, f, indent=2)

    result = validator.validate(temp_file)

    if is_valid:
        assert result.is_valid
    else:
        assert not result.is_valid
        assert any(
            err.rule
            == Rule.MANDATORY_MULTIPLE_SCORES_WITH_SAME_VERSION_PER_PRODUCT.name
            and error_message_part in err.message
            for err in result.errors
        )
    temp_file.unlink()


def test_mandatory_invalid_cvss(data_path, csaf_schema_path):
    """
    6.1.8 Invalid CVSS
    It MUST be tested that the given CVSS object is valid according to the
    referenced schema.
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory for Invalid CVSS",
            "tracking": {
                "id": "TEST-2023-0008",
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
            "category": "csaf_base",
        },
        "product_tree": {
            "full_product_names": [
                {"product_id": "CSAFPID-0001", "name": "Product A"},
            ],
        },
        "vulnerabilities": [
            {
                "title": "Vulnerability 1",
                "scores": [
                    {
                        "products": ["CSAFPID-0001"],
                        "cvss_v3": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "baseScore": 7.5,
                            # "baseSeverity": "HIGH",  # Missing
                        },
                    }
                ],
            }
        ],
    }

    validator = Validator(csaf_schema_path)
    doc = copy.deepcopy(base_csaf_doc)

    temp_file = data_path / "temp_invalid_cvss.json"
    with open(temp_file, "w") as f:
        json.dump(doc, f, indent=2)

    result = validator.validate(temp_file)

    assert not result.is_valid
    assert any(
        err.rule == Rule.MANDATORY_INVALID_CVSS.name
        and "missing the required 'baseSeverity' field" in err.message
        for err in result.errors
    )
    temp_file.unlink()


@pytest.mark.parametrize(
    "scores, is_valid, error_message_part",
    [
        # Valid: CVSS v3.1 correct
        (
            [
                {
                    "products": ["CSAFPID-0001"],
                    "cvss_v3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                    },
                }
            ],
            True,
            None,
        ),
        # Valid: CVSS v2.0 correct
        (
            [
                {
                    "products": ["CSAFPID-0001"],
                    "cvss_v2": {
                        "version": "2.0",
                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                        "baseScore": 7.5,
                    },
                }
            ],
            True,
            None,
        ),
        # Invalid: CVSS v3.1 incorrect baseScore
        (
            [
                {
                    "products": ["CSAFPID-0001"],
                    "cvss_v3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "baseScore": 7.4,  # Incorrect
                        "baseSeverity": "HIGH",
                    },
                }
            ],
            False,
            "baseScore in vulnerability 0, score 0 is 7.4, but should be 7.5",
        ),
        # Invalid: CVSS v3.1 incorrect baseSeverity
        (
            [
                {
                    "products": ["CSAFPID-0001"],
                    "cvss_v3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "baseScore": 7.5,
                        "baseSeverity": "MEDIUM",  # Incorrect
                    },
                }
            ],
            False,
            "baseSeverity in vulnerability 0, score 0 is 'MEDIUM', but should be 'High'",
        ),
        # Invalid: CVSS v2.0 incorrect baseScore
        (
            [
                {
                    "products": ["CSAFPID-0001"],
                    "cvss_v2": {
                        "version": "2.0",
                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                        "baseScore": 7.4,  # Incorrect
                    },
                }
            ],
            False,
            "baseScore in vulnerability 0, score 0 is 7.4, but should be 7.5",
        ),
    ],
)
def test_mandatory_invalid_cvss_computation(
    scores, is_valid, error_message_part, data_path, csaf_schema_path
):
    """
    6.1.9 Invalid CVSS computation
    It MUST be tested that the given CVSS object has the values computed
    correctly according to the definition.
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory",
            "tracking": {
                "id": "TEST-2023-0008",
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
            "category": "csaf_base",
        },
        "product_tree": {
            "full_product_names": [
                {"product_id": "CSAFPID-0001", "name": "Product A"},
            ],
        },
        "vulnerabilities": [
            {
                "title": "Vulnerability 1",
                "scores": scores,
            }
        ],
    }

    validator = Validator(csaf_schema_path)
    doc = copy.deepcopy(base_csaf_doc)

    temp_file = data_path / "temp_invalid_cvss_computation.json"
    with open(temp_file, "w") as f:
        json.dump(doc, f, indent=2)

    result = validator.validate(temp_file)

    if is_valid:
        assert result.is_valid
    else:
        assert not result.is_valid
        assert any(
            err.rule == Rule.MANDATORY_INVALID_CVSS_COMPUTATION.name
            and error_message_part in err.message
            for err in result.errors
        )
    temp_file.unlink()

    def test_mandatory_inconsistent_cvss(data_path, csaf_schema_path):
        """

        6.1.10 Inconsistent CVSS



        It MUST be tested that the given CVSS properties do not contradict the CVSS vector.



        """

        base_csaf_doc = {
            "document": {
                "csaf_version": "2.0",
                "publisher": {
                    "category": "vendor",
                    "name": "Example Company",
                    "namespace": "https://example.com",
                },
                "title": "Test Advisory",
                "tracking": {
                    "id": "TEST-2023-0009",
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
                "category": "csaf_base",
            },
            "product_tree": {
                "full_product_names": [
                    {"product_id": "CSAFPID-0001", "name": "Product A"},
                ],
            },
            "vulnerabilities": [
                {
                    "title": "Vulnerability 1",
                    "scores": [],
                }
            ],
        }

        validator = Validator(csaf_schema_path)

        # Test case 1: Consistent CVSS v3.1

        doc1 = copy.deepcopy(base_csaf_doc)

        doc1["vulnerabilities"][0]["scores"].append(
            {
                "products": ["CSAFPID-0001"],
                "cvss_v3": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "baseScore": 7.5,
                    "baseSeverity": "HIGH",
                    "attackVector": "NETWORK",
                    "attackComplexity": "LOW",
                    "privilegesRequired": "NONE",
                    "userInteraction": "NONE",
                    "scope": "UNCHANGED",
                    "confidentialityImpact": "HIGH",
                    "integrityImpact": "NONE",
                    "availabilityImpact": "NONE",
                },
            }
        )

        temp_file1 = data_path / "temp_consistent_cvss_v3.json"

        with open(temp_file1, "w") as f:

            json.dump(doc1, f, indent=2)

        result1 = validator.validate(temp_file1)

        assert result1.is_valid

        temp_file1.unlink()

        # Test case 2: Inconsistent CVSS v3.1

        doc2 = copy.deepcopy(base_csaf_doc)

        doc2["vulnerabilities"][0]["scores"].append(
            {
                "products": ["CSAFPID-0001"],
                "cvss_v3": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "baseScore": 7.5,
                    "baseSeverity": "HIGH",
                    "attackVector": "LOCAL",  # Inconsistent
                },
            }
        )

        temp_file2 = data_path / "temp_inconsistent_cvss_v3.json"

        with open(temp_file2, "w") as f:

            json.dump(doc2, f, indent=2)

        result2 = validator.validate(temp_file2)

        assert not result2.is_valid

        assert any(
            err.rule == Rule.MANDATORY_INCONSISTENT_CVSS.name
            and "attackVector" in err.message
            and "LOCAL" in err.message
            and "NETWORK" in err.message
            for err in result2.errors
        )

        temp_file2.unlink()

        # Test case 3: Consistent CVSS v2.0

        doc3 = copy.deepcopy(base_csaf_doc)

        doc3["vulnerabilities"][0]["scores"].append(
            {
                "products": ["CSAFPID-0001"],
                "cvss_v2": {
                    "version": "2.0",
                    "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                    "baseScore": 7.5,
                    "accessVector": "NETWORK",
                    "accessComplexity": "LOW",
                    "authentication": "NONE",
                    "confidentialityImpact": "PARTIAL",
                    "integrityImpact": "PARTIAL",
                    "availabilityImpact": "PARTIAL",
                },
            }
        )

        temp_file3 = data_path / "temp_consistent_cvss_v2.json"

        with open(temp_file3, "w") as f:

            json.dump(doc3, f, indent=2)

        result3 = validator.validate(temp_file3)

        assert result3.is_valid

        temp_file3.unlink()

        # Test case 4: Inconsistent CVSS v2.0

        doc4 = copy.deepcopy(base_csaf_doc)

        doc4["vulnerabilities"][0]["scores"].append(
            {
                "products": ["CSAFPID-0001"],
                "cvss_v2": {
                    "version": "2.0",
                    "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                    "baseScore": 7.5,
                    "accessVector": "LOCAL",  # Inconsistent
                },
            }
        )

        temp_file4 = data_path / "temp_inconsistent_cvss_v2.json"

        with open(temp_file4, "w") as f:

            json.dump(doc4, f, indent=2)

        result4 = validator.validate(temp_file4)

        assert not result4.is_valid

        assert any(
            err.rule == Rule.MANDATORY_INCONSISTENT_CVSS.name
            and "accessVector" in err.message
            and "LOCAL" in err.message
            and "NETWORK" in err.message
            for err in result4.errors
        )

        temp_file4.unlink()

        @pytest.mark.parametrize(
            "cwe, is_valid, error_message_part",
            [
                # Valid: Correct CWE ID and name
                (
                    {
                        "id": "CWE-79",
                        "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                    },
                    True,
                    None,
                ),
                # Invalid: Non-existent CWE ID
                (
                    {"id": "CWE-99999", "name": "Non-existent CWE"},
                    False,
                    "CWE ID 'CWE-99999' in vulnerability 0 does not exist.",
                ),
                # Invalid: Correct CWE ID, incorrect name
                (
                    {"id": "CWE-79", "name": "Improper Input Validation"},
                    False,
                    "CWE name for 'CWE-79' in vulnerability 0 is 'Improper Input Validation', but should be "
                    "'Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')'.",
                ),
                # Invalid: Malformed CWE ID
                (
                    {"id": "CWE-ABC", "name": "Malformed ID"},
                    False,
                    "Invalid CWE ID format 'CWE-ABC' in vulnerability 0.",
                ),
            ],
        )
        def test_mandatory_cwe(
            cwe, is_valid, error_message_part, data_path, csaf_schema_path
        ):
            """

            6.1.11 CWE



            It MUST be tested that given CWE exists and is valid.



            """

            base_csaf_doc = {
                "document": {
                    "csaf_version": "2.0",
                    "publisher": {
                        "category": "vendor",
                        "name": "Example Company",
                        "namespace": "https://example.com",
                    },
                    "title": "Test Advisory for CWE",
                    "tracking": {
                        "id": "TEST-2023-0010",
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
                    "category": "csaf_base",
                },
                "vulnerabilities": [
                    {
                        "title": "Vulnerability with CWE",
                        "cwe": cwe,
                    }
                ],
            }

            validator = Validator(csaf_schema_path)

            doc = copy.deepcopy(base_csaf_doc)

            temp_file = data_path / "temp_cwe_test.json"

            with open(temp_file, "w") as f:

                json.dump(doc, f, indent=2)

            result = validator.validate(temp_file)

            if is_valid:

                assert result.is_valid

            else:

                assert not result.is_valid

                assert any(
                    err.rule == Rule.MANDATORY_CWE.name
                    and error_message_part in err.message
                    for err in result.errors
                )

            temp_file.unlink()

        @pytest.mark.parametrize(
            "involvements, is_valid, error_message_part",
            [
                # Valid: No duplicates
                (
                    [
                        {
                            "party": "vendor",
                            "status": "in_progress",
                            "date": "2023-01-01T00:00:00Z",
                        },
                        {
                            "party": "researcher",
                            "status": "completed",
                            "date": "2023-01-01T00:00:00Z",
                        },
                    ],
                    True,
                    None,
                ),
                # Valid: Same party, different dates
                (
                    [
                        {
                            "party": "vendor",
                            "status": "in_progress",
                            "date": "2023-01-01T00:00:00Z",
                        },
                        {
                            "party": "vendor",
                            "status": "completed",
                            "date": "2023-01-02T00:00:00Z",
                        },
                    ],
                    True,
                    None,
                ),
                # Invalid: Same party, same date
                (
                    [
                        {
                            "party": "vendor",
                            "status": "in_progress",
                            "date": "2023-01-01T00:00:00Z",
                        },
                        {
                            "party": "vendor",
                            "status": "completed",
                            "date": "2023-01-01T00:00:00Z",
                        },
                    ],
                    False,
                    "Duplicate involvement for party 'vendor' on date '2023-01-01T00:00:00Z'",
                ),
            ],
        )
        def test_mandatory_multiple_definition_in_involvements(
            involvements, is_valid, error_message_part, data_path, csaf_schema_path
        ):
            """
            6.1.24 Multiple Definition in Involvements
            """
            base_csaf_doc = {
                "document": {
                    "csaf_version": "2.0",
                    "publisher": {
                        "category": "vendor",
                        "name": "Example Company",
                        "namespace": "https://example.com",
                    },
                    "title": "Test Advisory for Involvements",
                    "tracking": {
                        "id": "TEST-2023-0019",
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
                    "category": "csaf_base",
                },
                "vulnerabilities": [
                    {
                        "title": "Vulnerability with Involvements",
                        "involvements": involvements,
                    }
                ],
            }

            validator = Validator(csaf_schema_path)
            doc = copy.deepcopy(base_csaf_doc)

            temp_file = data_path / "temp_involvements_test.json"
            with open(temp_file, "w") as f:
                json.dump(doc, f, indent=2)

            result = validator.validate(temp_file)

            if is_valid:
                assert result.is_valid
            else:
                assert not result.is_valid
                assert any(
                    err.rule == Rule.MANDATORY_MULTIPLE_DEFINITION_IN_INVOLVEMENTS.name
                    and error_message_part in err.message
                    for err in result.errors
                )
            temp_file.unlink()

        @pytest.mark.skip(reason="Not implemented yet")
        def test_mandatory_multiple_use_of_same_hash_algorithm():
            """
            6.1.25 Multiple Use of Same Hash Algorithm
            """
            pass

        @pytest.mark.parametrize(
            "lang, source_lang, is_valid, error_message_part",
            [
                # Valid: Correct language tags
                ("en-US", "de", True, None),
                # Valid: Only lang is present
                ("fr-CA", None, True, None),
                # Valid: Only source_lang is present
                (None, "ja", True, None),
                # Invalid: Invalid lang tag
                (
                    "EZ",
                    "de",
                    False,
                    "Language tag 'EZ' in /document/lang is not a valid language code.",
                ),
                # Invalid: Invalid source_lang tag
                (
                    "en-US",
                    "invalid-lang",
                    False,
                    "Language tag 'invalid-lang' in /document/source_lang is not a valid language code.",
                ),
                # Invalid: Both lang and source_lang are invalid
                (
                    "EZ",
                    "invalid-lang",
                    False,
                    "Language tag 'EZ' in /document/lang is not a valid language code.",
                ),
            ],
        )
        def test_mandatory_language(
            lang, source_lang, is_valid, error_message_part, data_path, csaf_schema_path
        ):
            """

            6.1.12 Language



            For each element of type /$defs/language_t it MUST be tested that the



            language code is valid and exists.



            """

            base_csaf_doc = {
                "document": {
                    "csaf_version": "2.0",
                    "publisher": {
                        "category": "vendor",
                        "name": "Example Company",
                        "namespace": "https://example.com",
                    },
                    "title": "Test Advisory for Language",
                    "tracking": {
                        "id": "TEST-2023-0011",
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
                    "category": "csaf_base",
                },
            }

            validator = Validator(csaf_schema_path)

            doc = copy.deepcopy(base_csaf_doc)

            if lang:

                doc["document"]["lang"] = lang

            if source_lang:

                doc["document"]["source_lang"] = source_lang

            temp_file = data_path / "temp_language_test.json"

            with open(temp_file, "w") as f:

                json.dump(doc, f, indent=2)

            result = validator.validate(temp_file)

            if is_valid:

                assert result.is_valid

            else:

                assert not result.is_valid

                assert any(
                    err.rule == Rule.MANDATORY_LANGUAGE.name
                    and error_message_part in err.message
                    for err in result.errors
                )

            temp_file.unlink()


def test_mandatory_purl(data_path, csaf_schema_path):
    """
    6.1.13 PURL
    It MUST be tested that given PURL is valid.
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory for PURL",
            "tracking": {
                "id": "TEST-2023-0012",
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
            "category": "csaf_base",
        },
        "product_tree": {
            "full_product_names": [
                {
                    "product_id": "CSAFPID-0001",
                    "name": "Product A",
                    "product_identification_helper": {
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"
                    },
                },
                {
                    "product_id": "CSAFPID-0002",
                    "name": "Product B",
                    "product_identification_helper": {
                        "purl": "pkg:maven/@1.3.4"  # Invalid PURL
                    },
                },
            ]
        },
    }

    validator = Validator(csaf_schema_path)
    doc = copy.deepcopy(base_csaf_doc)

    temp_file = data_path / "temp_purl_test.json"
    with open(temp_file, "w") as f:
        json.dump(doc, f, indent=2)

    result = validator.validate(temp_file)

    assert not result.is_valid
    assert any(
        err.rule == Rule.MANDATORY_PURL.name
        and "Invalid PURL 'pkg:maven/@1.3.4'" in err.message
        for err in result.errors
    )

    temp_file.unlink()


def test_mandatory_sorted_revision_history(data_path, csaf_schema_path):
    """
    6.1.14 Sorted Revision History
    It MUST be tested that the value of `number` of items of the revision
    history are sorted ascending when the items are sorted ascending by `date`.
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory for Revision History",
            "tracking": {
                "id": "TEST-2023-0013",
                "status": "final",
                "version": "2",
                "initial_release_date": "2023-01-01T00:00:00Z",
                "current_release_date": "2023-01-02T00:00:00Z",
                "revision_history": [],
            },
            "category": "csaf_base",
        },
    }

    validator = Validator(csaf_schema_path)

    # Test case 1: Valid sorted revision history
    doc1 = copy.deepcopy(base_csaf_doc)
    doc1["document"]["tracking"]["revision_history"] = [
        {
            "date": "2023-01-01T00:00:00Z",
            "number": "1",
            "summary": "Initial release",
        },
        {
            "date": "2023-01-02T00:00:00Z",
            "number": "2",
            "summary": "Second release",
        },
    ]
    temp_file1 = data_path / "temp_sorted_revision_history_valid.json"
    with open(temp_file1, "w") as f:
        json.dump(doc1, f, indent=2)
    result1 = validator.validate(temp_file1)
    assert result1.is_valid
    temp_file1.unlink()

    # Test case 2: Invalid sorted revision history
    doc2 = copy.deepcopy(base_csaf_doc)
    doc2["document"]["tracking"]["revision_history"] = [
        {
            "date": "2023-01-01T00:00:00Z",
            "number": "2",
            "summary": "Initial release with wrong number",
        },
        {
            "date": "2023-01-02T00:00:00Z",
            "number": "1",
            "summary": "Second release with wrong number",
        },
    ]
    doc2["document"]["tracking"]["version"] = "1"
    temp_file2 = data_path / "temp_sorted_revision_history_invalid.json"
    with open(temp_file2, "w") as f:
        json.dump(doc2, f, indent=2)
    result2 = validator.validate(temp_file2)
    assert not result2.is_valid
    assert any(
        err.rule == Rule.MANDATORY_SORTED_REVISION_HISTORY.name
        and "Revision history numbers are not sorted correctly" in err.message
        for err in result2.errors
    )
    temp_file2.unlink()


def test_mandatory_translator(data_path, csaf_schema_path):
    """
    6.1.15 Translator
    It MUST be tested that `/document/source_lang` is present and set if
    the value `translator` is used for `/document/publisher/category`.
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory for Translator",
            "tracking": {
                "id": "TEST-2023-0014",
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
            "category": "csaf_base",
        },
    }

    validator = Validator(csaf_schema_path)

    # Test case 1: Valid translator document
    doc1 = copy.deepcopy(base_csaf_doc)
    doc1["document"]["publisher"]["category"] = "translator"
    doc1["document"]["source_lang"] = "en"
    temp_file1 = data_path / "temp_translator_valid.json"
    with open(temp_file1, "w") as f:
        json.dump(doc1, f, indent=2)
    result1 = validator.validate(temp_file1)
    assert result1.is_valid
    temp_file1.unlink()

    # Test case 2: Invalid translator document (missing source_lang)
    doc2 = copy.deepcopy(base_csaf_doc)
    doc2["document"]["publisher"]["category"] = "translator"
    temp_file2 = data_path / "temp_translator_invalid.json"
    with open(temp_file2, "w") as f:
        json.dump(doc2, f, indent=2)
    result2 = validator.validate(temp_file2)
    assert not result2.is_valid
    assert any(
        err.rule == Rule.MANDATORY_TRANSLATOR.name
        and "'/document/source_lang' must be present" in err.message
        for err in result2.errors
    )
    temp_file2.unlink()

    # Test case 3: Non-translator document (should be valid)
    doc3 = copy.deepcopy(base_csaf_doc)
    doc3["document"]["publisher"]["category"] = "vendor"
    temp_file3 = data_path / "temp_translator_not_applicable.json"
    with open(temp_file3, "w") as f:
        json.dump(doc3, f, indent=2)
    result3 = validator.validate(temp_file3)
    assert result3.is_valid
    temp_file3.unlink()


@pytest.mark.parametrize(
    "version, revision_history, status, is_valid, error_message_part",
    [
        # Valid: Simple integer match
        (
            "2",
            [
                {"date": "2023-01-01T00:00:00Z", "number": "1", "summary": "Initial"},
                {"date": "2023-01-02T00:00:00Z", "number": "2", "summary": "Second"},
            ],
            "final",
            True,
            None,
        ),
        # Valid: Simple semver match
        (
            "1.1.0",
            [
                {
                    "date": "2023-01-01T00:00:00Z",
                    "number": "1.0.0",
                    "summary": "Initial",
                },
                {
                    "date": "2023-01-02T00:00:00Z",
                    "number": "1.1.0",
                    "summary": "Update",
                },
            ],
            "final",
            True,
            None,
        ),
        # Valid: Build metadata is ignored
        (
            "1.1.0+build123",
            [
                {
                    "date": "2023-01-01T00:00:00Z",
                    "number": "1.0.0",
                    "summary": "Initial",
                },
                {
                    "date": "2023-01-02T00:00:00Z",
                    "number": "1.1.0",
                    "summary": "Update",
                },
            ],
            "final",
            True,
            None,
        ),
        # Valid: Draft status, pre-release part is ignored
        (
            "1.1.0-alpha",
            [
                {
                    "date": "2023-01-01T00:00:00Z",
                    "number": "1.0.0",
                    "summary": "Initial",
                },
                {
                    "date": "2023-01-02T00:00:00Z",
                    "number": "1.1.0",
                    "summary": "Update",
                },
            ],
            "draft",
            True,
            None,
        ),
        # Invalid: Mismatch in version
        (
            "1",
            [
                {"date": "2023-01-01T00:00:00Z", "number": "1", "summary": "Initial"},
                {"date": "2023-01-02T00:00:00Z", "number": "2", "summary": "Second"},
            ],
            "final",
            False,
            "Document version '1' does not match the number of the latest revision history item '2'",
        ),
        # Invalid: Mismatch with build metadata
        (
            "1.1.0+build123",
            [
                {
                    "date": "2023-01-01T00:00:00Z",
                    "number": "1.0.0",
                    "summary": "Initial",
                },
                {
                    "date": "2023-01-02T00:00:00Z",
                    "number": "1.2.0",
                    "summary": "Update",
                },
            ],
            "final",
            False,
            "Document version '1.1.0+build123' does not match the number of the latest revision history item '1.2.0'",
        ),
        # Invalid: Final status, pre-release part is not ignored and causes mismatch
        (
            "1.1.0-alpha",
            [
                {
                    "date": "2023-01-01T00:00:00Z",
                    "number": "1.0.0",
                    "summary": "Initial",
                },
                {
                    "date": "2023-01-02T00:00:00Z",
                    "number": "1.1.0",
                    "summary": "Update",
                },
            ],
            "final",
            False,
            "Document version '1.1.0-alpha' does not match the number of the latest revision history item '1.1.0'",
        ),
    ],
)
def test_mandatory_latest_document_version(
    version,
    revision_history,
    status,
    is_valid,
    error_message_part,
    data_path,
    csaf_schema_path,
):
    """
    6.1.16 Latest Document Version
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory for Latest Document Version",
            "tracking": {
                "id": "TEST-2023-0015",
                "status": status,
                "version": version,
                "initial_release_date": "2023-01-01T00:00:00Z",
                "current_release_date": "2023-01-02T00:00:00Z",
                "revision_history": revision_history,
            },
            "category": "csaf_base",
        },
    }

    validator = Validator(csaf_schema_path)
    doc = copy.deepcopy(base_csaf_doc)

    temp_file = data_path / "temp_latest_document_version.json"
    with open(temp_file, "w") as f:
        json.dump(doc, f, indent=2)

    result = validator.validate(temp_file)

    if is_valid:
        assert result.is_valid
    else:
        assert not result.is_valid
        assert any(
            err.rule == Rule.MANDATORY_LATEST_DOCUMENT_VERSION.name
            and error_message_part in err.message
            for err in result.errors
        )
    temp_file.unlink()


@pytest.mark.parametrize(
    "version, status, is_valid, error_message_part",
    [
        # Valid: Draft status with 0.y.z version
        ("0.9.0", "draft", True, None),
        # Valid: Draft status with pre-release version
        ("1.0.0-alpha", "draft", True, None),
        # Valid: Final status with release version
        ("1.0.0", "final", True, None),
        # Invalid: Final status with 0.y.z version
        (
            "0.9.5",
            "final",
            False,
            "indicates a pre-release, but status is 'final' instead of 'draft'",
        ),
        # Invalid: Interim status with pre-release version
        (
            "1.0.0-beta",
            "interim",
            False,
            "indicates a pre-release, but status is 'interim' instead of 'draft'",
        ),
    ],
)
def test_mandatory_document_status_draft(
    version, status, is_valid, error_message_part, data_path, csaf_schema_path
):
    """
    6.1.17 Document Status Draft
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory for Document Status Draft",
            "tracking": {
                "id": "TEST-2023-0016",
                "status": status,
                "version": version,
                "initial_release_date": "2023-01-01T00:00:00Z",
                "current_release_date": "2023-01-01T00:00:00Z",
                "revision_history": [
                    {
                        "date": "2023-01-01T00:00:00Z",
                        "number": version.split("-")[0],
                        "summary": "Initial release",
                    }
                ],
            },
            "category": "csaf_base",
        },
    }

    validator = Validator(csaf_schema_path)
    doc = copy.deepcopy(base_csaf_doc)

    temp_file = data_path / "temp_document_status_draft.json"
    with open(temp_file, "w") as f:
        json.dump(doc, f, indent=2)

    result = validator.validate(temp_file)

    if is_valid:
        assert result.is_valid
    else:
        assert not result.is_valid
        assert any(
            err.rule == Rule.MANDATORY_DOCUMENT_STATUS_DRAFT.name
            and error_message_part in err.message
            for err in result.errors
        )
    temp_file.unlink()


def test_mandatory_released_revision_history(data_path, csaf_schema_path):
    """
    6.1.18 Released Revision History
    It MUST be tested that no item of the revision history has a `number` of `0`
    or `0.y.z` when the document status is `final` or `interim`.
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory for Released Revision History",
            "tracking": {
                "id": "TEST-2023-0017",
                "initial_release_date": "2023-01-01T00:00:00Z",
                "current_release_date": "2023-01-02T00:00:00Z",
                "revision_history": [],
                "status": "final",
                "version": "1.0.0",
            },
            "category": "csaf_base",
        },
    }

    validator = Validator(csaf_schema_path)

    # Test case 1: Invalid - status 'final' with revision '0'
    doc1 = copy.deepcopy(base_csaf_doc)
    doc1["document"]["tracking"]["revision_history"] = [
        {"date": "2023-01-01T00:00:00Z", "number": "0", "summary": "Draft"},
        {"date": "2023-01-02T00:00:00Z", "number": "1.0.0", "summary": "Final"},
    ]
    doc1["document"]["tracking"]["status"] = "final"
    temp_file1 = data_path / "temp_released_rev_history_final_invalid.json"
    with open(temp_file1, "w") as f:
        json.dump(doc1, f, indent=2)
    result1 = validator.validate(temp_file1)
    assert not result1.is_valid
    assert any(
        err.rule == Rule.MANDATORY_RELEASED_REVISION_HISTORY.name
        and "not allowed when document status is 'final'" in err.message
        for err in result1.errors
    )
    temp_file1.unlink()

    # Test case 2: Invalid - status 'interim' with revision '0.1.0'
    doc2 = copy.deepcopy(base_csaf_doc)
    doc2["document"]["tracking"]["revision_history"] = [
        {"date": "2023-01-01T00:00:00Z", "number": "0.1.0", "summary": "Draft"},
        {"date": "2023-01-02T00:00:00Z", "number": "1.0.0", "summary": "Final"},
    ]
    doc2["document"]["tracking"]["status"] = "interim"
    temp_file2 = data_path / "temp_released_rev_history_interim_invalid.json"
    with open(temp_file2, "w") as f:
        json.dump(doc2, f, indent=2)
    result2 = validator.validate(temp_file2)
    assert not result2.is_valid
    assert any(
        err.rule == Rule.MANDATORY_RELEASED_REVISION_HISTORY.name
        and "not allowed when document status is 'interim'" in err.message
        for err in result2.errors
    )
    temp_file2.unlink()

    # Test case 3: Valid - status 'draft' with revision '0'
    doc3 = copy.deepcopy(base_csaf_doc)
    doc3["document"]["tracking"]["revision_history"] = [
        {"date": "2023-01-01T00:00:00Z", "number": "0", "summary": "Draft"}
    ]
    doc3["document"]["tracking"]["status"] = "draft"
    doc3["document"]["tracking"]["version"] = "0"
    temp_file3 = data_path / "temp_released_rev_history_draft_valid.json"
    with open(temp_file3, "w") as f:
        json.dump(doc3, f, indent=2)
    result3 = validator.validate(temp_file3)
    assert result3.is_valid
    temp_file3.unlink()

    # Test case 4: Valid - status 'final' without '0' revisions
    doc4 = copy.deepcopy(base_csaf_doc)
    doc4["document"]["tracking"]["revision_history"] = [
        {"date": "2023-01-02T00:00:00Z", "number": "1.0.0", "summary": "Final"}
    ]
    doc4["document"]["tracking"]["status"] = "final"
    temp_file4 = data_path / "temp_released_rev_history_final_valid.json"
    with open(temp_file4, "w") as f:
        json.dump(doc4, f, indent=2)
    result4 = validator.validate(temp_file4)
    assert result4.is_valid
    temp_file4.unlink()


@pytest.mark.parametrize(
    "revision_history, is_valid, error_message_part",
    [
        # Valid: No pre-release versions in revision history
        (
            [
                {
                    "date": "2023-01-01T00:00:00Z",
                    "number": "1.0.0",
                    "summary": "Initial",
                },
                {
                    "date": "2023-01-02T00:00:00Z",
                    "number": "2.0.0",
                    "summary": "Second",
                },
            ],
            True,
            None,
        ),
        # Invalid: Pre-release version in revision history
        (
            [
                {
                    "date": "2023-01-01T00:00:00Z",
                    "number": "1.0.0-alpha",
                    "summary": "Initial",
                },
                {"date": "2023-01-02T00:00:00Z", "number": "1.0.0", "summary": "Final"},
            ],
            False,
            "contains pre-release information",
        ),
    ],
)
def test_mandatory_revision_history_entries_for_pre_release_versions(
    revision_history, is_valid, error_message_part, data_path, csaf_schema_path
):
    """
    6.1.19 Revision History Entries for Pre-release Versions
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory for Pre-release in Revision History",
            "tracking": {
                "id": "TEST-2023-0018",
                "status": "final",
                "version": "1.0.0",
                "initial_release_date": "2023-01-01T00:00:00Z",
                "current_release_date": "2023-01-02T00:00:00Z",
                "revision_history": revision_history,
            },
            "category": "csaf_base",
        },
    }

    validator = Validator(csaf_schema_path)
    doc = copy.deepcopy(base_csaf_doc)

    temp_file = data_path / "temp_pre_release_in_revision_history.json"
    with open(temp_file, "w") as f:
        json.dump(doc, f, indent=2)

    result = validator.validate(temp_file)

    if is_valid:
        assert not any(
            err.rule
            == Rule.MANDATORY_REVISION_HISTORY_ENTRIES_FOR_PRE_RELEASE_VERSIONS.name
            for err in result.errors
        )
    else:
        assert not result.is_valid
        assert any(
            err.rule
            == Rule.MANDATORY_REVISION_HISTORY_ENTRIES_FOR_PRE_RELEASE_VERSIONS.name
            and error_message_part in err.message
            for err in result.errors
        )

    temp_file.unlink()


@pytest.mark.parametrize(
    "version, status, is_valid, error_message_part",
    [
        # Valid: Final status with no pre-release version
        ("1.0.0", "final", True, None),
        # Valid: Interim status with no pre-release version
        ("2.0.0", "interim", True, None),
        # Valid: Draft status with pre-release version
        ("1.0.0-alpha", "draft", True, None),
        # Invalid: Final status with pre-release version
        (
            "1.0.0-alpha",
            "final",
            False,
            "Document version '1.0.0-alpha' contains a pre-release part",
        ),
        # Invalid: Interim status with pre-release version
        (
            "2.0.0-rc1",
            "interim",
            False,
            "Document version '2.0.0-rc1' contains a pre-release part",
        ),
    ],
)
def test_mandatory_non_draft_document_version(
    version, status, is_valid, error_message_part, data_path, csaf_schema_path
):
    """
    6.1.20 Non-draft Document Version
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory for Non-draft Document Version",
            "tracking": {
                "id": "TEST-2023-0019",
                "status": status,
                "version": version,
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
            "category": "csaf_base",
        },
    }

    validator = Validator(csaf_schema_path)
    doc = copy.deepcopy(base_csaf_doc)

    temp_file = data_path / "temp_non_draft_document_version.json"
    with open(temp_file, "w") as f:
        json.dump(doc, f, indent=2)

    result = validator.validate(temp_file)

    if is_valid:
        assert not any(
            err.rule == Rule.MANDATORY_NON_DRAFT_DOCUMENT_VERSION.name
            for err in result.errors
        )
    else:
        assert not result.is_valid
        assert any(
            err.rule == Rule.MANDATORY_NON_DRAFT_DOCUMENT_VERSION.name
            and error_message_part in err.message
            for err in result.errors
        )

    temp_file.unlink()


@pytest.mark.parametrize(
    "revision_history, is_valid, error_message_part",
    [
        # Valid: No missing versions
        (
            [
                {"date": "2023-01-01T00:00:00Z", "number": "1", "summary": "Initial"},
                {"date": "2023-01-02T00:00:00Z", "number": "2", "summary": "Second"},
            ],
            True,
            None,
        ),
        # Invalid: Missing version
        (
            [
                {"date": "2023-01-01T00:00:00Z", "number": "1", "summary": "Initial"},
                {"date": "2023-01-03T00:00:00Z", "number": "3", "summary": "Third"},
            ],
            False,
            "missing a version number between 1 and 3",
        ),
    ],
)
def test_mandatory_missing_item_in_revision_history(
    revision_history, is_valid, error_message_part, data_path, csaf_schema_path
):
    """
    6.1.21 Missing Item in Revision History
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory for Missing Item in Revision History",
            "tracking": {
                "id": "TEST-2023-0020",
                "status": "final",
                "version": "3",
                "initial_release_date": "2023-01-01T00:00:00Z",
                "current_release_date": "2023-01-03T00:00:00Z",
                "revision_history": revision_history,
            },
            "category": "csaf_base",
        },
    }

    validator = Validator(csaf_schema_path)
    doc = copy.deepcopy(base_csaf_doc)

    temp_file = data_path / "temp_missing_item_in_revision_history.json"
    with open(temp_file, "w") as f:
        json.dump(doc, f, indent=2)

    result = validator.validate(temp_file)

    if is_valid:
        assert not any(
            err.rule == Rule.MANDATORY_MISSING_ITEM_IN_REVISION_HISTORY.name
            for err in result.errors
        )
    else:
        assert not result.is_valid
        assert any(
            err.rule == Rule.MANDATORY_MISSING_ITEM_IN_REVISION_HISTORY.name
            and error_message_part in err.message
            for err in result.errors
        )

    temp_file.unlink()


@pytest.mark.parametrize(
    "revision_history, is_valid, error_message_part",
    [
        # Valid: No duplicate version numbers
        (
            [
                {
                    "date": "2023-01-01T00:00:00Z",
                    "number": "1.0.0",
                    "summary": "Initial",
                },
                {
                    "date": "2023-01-02T00:00:00Z",
                    "number": "2.0.0",
                    "summary": "Second",
                },
            ],
            True,
            None,
        ),
        # Invalid: Duplicate version number
        (
            [
                {
                    "date": "2023-01-01T00:00:00Z",
                    "number": "1.0.0",
                    "summary": "Initial",
                },
                {
                    "date": "2023-01-02T00:00:00Z",
                    "number": "1.0.0",
                    "summary": "Duplicate",
                },
            ],
            False,
            "Revision history contains duplicate version number '1.0.0'",
        ),
    ],
)
def test_mandatory_multiple_definition_in_revision_history(
    revision_history, is_valid, error_message_part, data_path, csaf_schema_path
):
    """
    6.1.22 Multiple Definition in Revision History
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory for Duplicate Revision History",
            "tracking": {
                "id": "TEST-2023-0021",
                "status": "final",
                "version": "2.0.0",
                "initial_release_date": "2023-01-01T00:00:00Z",
                "current_release_date": "2023-01-02T00:00:00Z",
                "revision_history": revision_history,
            },
            "category": "csaf_base",
        },
    }

    validator = Validator(csaf_schema_path)
    doc = copy.deepcopy(base_csaf_doc)

    temp_file = data_path / "temp_duplicate_revision_history.json"
    with open(temp_file, "w") as f:
        json.dump(doc, f, indent=2)

    result = validator.validate(temp_file)

    if is_valid:
        assert not any(
            err.rule == Rule.MANDATORY_MULTIPLE_DEFINITION_IN_REVISION_HISTORY.name
            for err in result.errors
        )
    else:
        assert not result.is_valid
        assert any(
            err.rule == Rule.MANDATORY_MULTIPLE_DEFINITION_IN_REVISION_HISTORY.name
            and error_message_part in err.message
            for err in result.errors
        )

    temp_file.unlink()


@pytest.mark.parametrize(
    "vulnerabilities, is_valid, error_message_part",
    [
        # Valid: No duplicate CVEs
        (
            [{"cve": "CVE-2021-44228"}, {"cve": "CVE-2021-45046"}],
            True,
            None,
        ),
        # Invalid: Duplicate CVE
        (
            [{"cve": "CVE-2021-44228"}, {"cve": "CVE-2021-44228"}],
            False,
            "CVE 'CVE-2021-44228' is used in multiple vulnerability items.",
        ),
        # Valid: One vulnerability with a CVE, one without
        (
            [{"cve": "CVE-2021-44228"}, {"title": "Some other vulnerability"}],
            True,
            None,
        ),
    ],
)
def test_mandatory_multiple_use_of_same_cve(
    vulnerabilities, is_valid, error_message_part, data_path, csaf_schema_path
):
    """
    6.1.23 Multiple Use of Same CVE
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory for Multiple CVE Use",
            "tracking": {
                "id": "TEST-2023-0022",
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
            "category": "csaf_base",
        },
        "vulnerabilities": vulnerabilities,
    }

    validator = Validator(csaf_schema_path)
    doc = copy.deepcopy(base_csaf_doc)

    temp_file = data_path / "temp_multiple_cve_use.json"
    with open(temp_file, "w") as f:
        json.dump(doc, f, indent=2)

    result = validator.validate(temp_file)

    if is_valid:
        assert not any(
            err.rule == Rule.MANDATORY_MULTIPLE_USE_OF_SAME_CVE.name
            for err in result.errors
        )
    else:
        assert not result.is_valid
        assert any(
            err.rule == Rule.MANDATORY_MULTIPLE_USE_OF_SAME_CVE.name
            and error_message_part in err.message
            for err in result.errors
        )

    temp_file.unlink()


@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_multiple_use_of_same_hash_algorithm():
    """
    6.1.25 Multiple Use of Same Hash Algorithm
    It MUST be tested that the same hash algorithm is not used multiple times
    in one item of hashes.
    """
    pass


@pytest.mark.parametrize(
    "category, is_valid, error_message_part",
    [
        # Valid: Standard CSAF Base category
        ("csaf_base", True, None),
        # Valid: Custom category that doesn't conflict
        ("Example Company Security Notice", True, None),
        # Invalid: Conflicts with a standard profile name
        ("Security Advisory", False, "prohibited name"),
        ("informational-advisory", False, "prohibited name"),
        ("VEX", False, "prohibited name"),
    ],
)
def test_mandatory_prohibited_document_category_name(
    category, is_valid, error_message_part, data_path, csaf_schema_path
):
    """
    6.1.26 Prohibited Document Category Name
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory for Prohibited Category",
            "tracking": {
                "id": "TEST-2023-0025",
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
            "category": category,
        },
    }

    validator = Validator(csaf_schema_path)
    doc = copy.deepcopy(base_csaf_doc)

    temp_file = data_path / "temp_prohibited_category.json"
    with open(temp_file, "w") as f:
        json.dump(doc, f, indent=2)

    result = validator.validate(temp_file)

    if is_valid:
        assert not any(
            err.rule == Rule.MANDATORY_PROHIBITED_DOCUMENT_CATEGORY_NAME.name
            for err in result.errors
        )
    else:
        assert not result.is_valid
        assert any(
            err.rule == Rule.MANDATORY_PROHIBITED_DOCUMENT_CATEGORY_NAME.name
            and error_message_part in err.message
            for err in result.errors
        )

    temp_file.unlink()

    @pytest.mark.parametrize(
        "branches, is_valid, error_message_part",
        [
            # Valid: No version range in product_version
            (
                [
                    {
                        "category": "product_version",
                        "name": "1.0",
                        "product": {
                            "product_id": "CSAFPID-0001",
                            "name": "Product A v1.0",
                        },
                    }
                ],
                True,
                None,
            ),
            # Invalid: Version range in product_version
            (
                [
                    {
                        "category": "product_version",
                        "name": "prior to 4.2",
                        "product": {"product_id": "CSAFPID-0001", "name": "Product A"},
                    }
                ],
                False,
                "contains a version range in 'name'",
            ),
        ],
    )
    def test_mandatory_version_range_in_product_version(
        branches, is_valid, error_message_part, data_path, csaf_schema_path
    ):
        """

        6.1.31 Version Range in Product Version

        """

        base_csaf_doc = {
            "document": {
                "csaf_version": "2.0",
                "publisher": {
                    "category": "vendor",
                    "name": "Example Company",
                    "namespace": "https://example.com",
                },
                "title": "Test Advisory for Version Range in Product Version",
                "tracking": {
                    "id": "TEST-2023-0029",
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
                "category": "csaf_base",
            },
            "product_tree": {"branches": branches},
        }

        validator = Validator(csaf_schema_path)

        doc = copy.deepcopy(base_csaf_doc)

        temp_file = data_path / "temp_version_range_in_product_version.json"

        with open(temp_file, "w") as f:

            json.dump(doc, f, indent=2)

        result = validator.validate(temp_file)

        if is_valid:

            assert not any(
                err.rule == Rule.MANDATORY_VERSION_RANGE_IN_PRODUCT_VERSION.name
                for err in result.errors
            )

        else:

            assert not result.is_valid

            assert any(
                err.rule == Rule.MANDATORY_VERSION_RANGE_IN_PRODUCT_VERSION.name
                and error_message_part in err.message
                for err in result.errors
            )

        temp_file.unlink()

    @pytest.mark.parametrize(
        "flags, is_valid, error_message_part",
        [
            # Valid: product_ids is present
            (
                [{"label": "component_not_present", "product_ids": ["CSAFPID-0001"]}],
                True,
                None,
            ),
            # Valid: group_ids is present
            (
                [{"label": "component_not_present", "group_ids": ["CSAFGID-0001"]}],
                True,
                None,
            ),
            # Invalid: Missing both product_ids and group_ids
            (
                [{"label": "component_not_present"}],
                False,
                "missing both 'group_ids' and 'product_ids'",
            ),
        ],
    )
    def test_mandatory_flag_without_product_reference(
        flags, is_valid, error_message_part, data_path, csaf_schema_path
    ):
        """

        6.1.32 Flag without Product Reference

        """

        base_csaf_doc = {
            "document": {
                "csaf_version": "2.0",
                "publisher": {
                    "category": "vendor",
                    "name": "Example Company",
                    "namespace": "https://example.com",
                },
                "title": "Test Advisory for Flag without Product Reference",
                "tracking": {
                    "id": "TEST-2023-0030",
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
                "category": "csaf_base",
            },
            "vulnerabilities": [{"title": "Vulnerability 1", "flags": flags}],
        }

        validator = Validator(csaf_schema_path)

        doc = copy.deepcopy(base_csaf_doc)

        temp_file = data_path / "temp_flag_without_product_reference.json"

        with open(temp_file, "w") as f:

            json.dump(doc, f, indent=2)

        result = validator.validate(temp_file)

        if is_valid:

            assert not any(
                err.rule == Rule.MANDATORY_FLAG_WITHOUT_PRODUCT_REFERENCE.name
                for err in result.errors
            )

        else:

            assert not result.is_valid

            assert any(
                err.rule == Rule.MANDATORY_FLAG_WITHOUT_PRODUCT_REFERENCE.name
                and error_message_part in err.message
                for err in result.errors
            )

        temp_file.unlink()

    ##################################################################

    #  6.2 Optional Tests

    ##################################################################


def test_mandatory_missing_product_group_id_definition(data_path, csaf_schema_path):
    """
    6.1.4 Missing Definition of Product Group ID
    For each element of type product_group_id_t that is not inside a product_group,
    it MUST be tested that the product_group element with the matching group_id exists.
    """
    base_csaf_doc = {
        "document": {
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Example Company",
                "namespace": "https://example.com",
            },
            "title": "Test Advisory",
            "tracking": {
                "id": "TEST-2023-0003",
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
            "category": "csaf_base",
        },
        "product_tree": {
            "full_product_names": [
                {"product_id": "CSAFPID-0001", "name": "Product A"},
                {"product_id": "CSAFPID-0002", "name": "Product B"},
            ],
            "product_groups": [
                {
                    "group_id": "CSAFGID-0001",
                    "product_ids": ["CSAFPID-0001", "CSAFPID-0002"],
                },
            ],
        },
        "vulnerabilities": [
            {
                "title": "Vulnerability 1",
                "product_status": {
                    "known_affected": ["CSAFPID-0001"],
                    "known_not_affected": ["CSAFPID-0002"],
                },
                "remediations": [
                    {
                        "category": "vendor_fix",
                        "details": "Apply update.",
                        "product_groups": ["CSAFGID-0001"],
                    }
                ],
            }
        ],
    }

    validator = Validator(csaf_schema_path)

    # Test case 1: Missing Product Group ID definition
    doc1 = copy.deepcopy(base_csaf_doc)
    doc1["vulnerabilities"][0]["remediations"][0]["product_groups"].append(
        "CSAFGID-0002"  # Referenced but not defined
    )
    temp_file1 = data_path / "temp_missing_product_group_id.json"
    with open(temp_file1, "w") as f:
        json.dump(doc1, f, indent=2)
    result1 = validator.validate(temp_file1)
    assert not result1.is_valid
    assert any(
        err.rule == Rule.MANDATORY_MISSING_PRODUCT_GROUP_ID_DEFINITION.name
        and (
            "Referenced product_group_id 'CSAFGID-0002' is not defined in "
            "the product_tree.product_groups."
        )
        in err.message
        for err in result1.errors
    )
    temp_file1.unlink()

    # Test case 2: All Product Group IDs correctly defined and referenced
    doc2 = copy.deepcopy(base_csaf_doc)
    temp_file2 = data_path / "temp_valid_product_group_id.json"
    with open(temp_file2, "w") as f:
        json.dump(doc2, f, indent=2)
    result2 = validator.validate(temp_file2)
    assert result2.is_valid
    temp_file2.unlink()


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_unused_product_id_definition():
    """
    6.2.1 Unused Definition of Product ID
    For each product_id_t in full_product_name_t elements, it MUST be tested
    that the product_id is referenced somewhere within the same document.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_missing_remediation():
    """
    6.2.2 Missing Remediation
    For each product_id_t in the Product Status groups Affected and Under
    investigation, it MUST be tested that a remediation exists.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_missing_score():
    """
    6.2.3 Missing Score
    For each product_id_t in the Product Status groups Affected, it MUST be
    tested that a score object exists which covers this product.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_build_metadata_in_revision_history():
    """
    6.2.4 Build Metadata in Revision History
    For each item in revision history, it MUST be tested that `number` does not
    include build metadata.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_older_initial_release_date_than_revision_history():
    """
    6.2.5 Older Initial Release Date than Revision History
    It MUST be tested that the Initial Release Date is not older than the `date`
    of the oldest item in Revision History.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_older_current_release_date_than_revision_history():
    """
    6.2.6 Older Current Release Date than Revision History
    It MUST be tested that the Current Release Date is not older than the `date`
    of the newest item in Revision History.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_missing_date_in_involvements():
    """
    6.2.7 Missing Date in Involvements
    For each item in the list of involvements, it MUST be tested that it
    includes the property `date`.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_use_of_md5_as_only_hash_algorithm():
    """
    6.2.8 Use of MD5 as the only Hash Algorithm
    It MUST be tested that the hash algorithm `md5` is not the only one present.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_use_of_sha1_as_only_hash_algorithm():
    """
    6.2.9 Use of SHA-1 as the only Hash Algorithm
    It MUST be tested that the hash algorithm `sha1` is not the only one present.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_missing_tlp_label():
    """
    6.2.10 Missing TLP label
    It MUST be tested that /document/distribution/tlp/label is present and valid.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_missing_canonical_url():
    """
    6.2.11 Missing Canonical URL
    It MUST be tested that the CSAF document has a canonical URL.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_missing_document_language():
    """
    6.2.12 Missing Document Language
    It MUST be tested that the document language is present and set.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_sorting():
    """
    6.2.13 Sorting
    It MUST be tested that all keys in a CSAF document are sorted alphabetically.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_use_of_private_language():
    """
    6.2.14 Use of Private Language
    For each element of type lang_t, it MUST be tested that the language code
    does not contain subtags reserved for private use.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_use_of_default_language():
    """
    6.2.15 Use of Default Language
    For each element of type lang_t, it MUST be tested that the language code
    is not `i-default`.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_missing_product_identification_helper():
    """
    6.2.16 Missing Product Identification Helper
    For each element of type full_product_name_t, it MUST be tested that it
    includes the property `product_identification_helper`.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_cve_in_field_ids():
    """
    6.2.17 CVE in field IDs
    For each item in /vulnerabilities[]/ids, it MUST be tested that it is not a CVE ID.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_product_version_range_without_vers():
    """
    6.2.18 Product Version Range without vers
    For each element of type branches_t with category of product_version_range,
    it MUST be tested that the value of `name` conforms the vers specification.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_cvss_for_fixed_products():
    """
    6.2.19 CVSS for Fixed Products
    For each item the fixed products group, it MUST be tested that a CVSS
    applying to this product has an environmental score of `0`.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_optional_additional_properties():
    """
    6.2.20 Additional Properties
    It MUST be tested that there is no additional property in the CSAF document
    that was not defined in the CSAF JSON schema.
    """
    pass


##################################################################
#  6.3 Informative Tests
##################################################################


@pytest.mark.skip(reason="Not implemented yet")
def test_informative_use_of_cvss_v2_as_only_scoring_system():
    """
    6.3.1 Use of CVSS v2 as the only Scoring System
    For each item in the list of scores which contains the `cvss_v2` object,
    it MUST be tested that is not the only scoring item present.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_informative_use_of_cvss_v3_0():
    """
    6.3.2 Use of CVSS v3.0
    For each item in the list of scores which contains the `cvss_v3` object,
    it MUST be tested that CVSS v3.0 is not used.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_informative_missing_cve():
    """
    6.3.3 Missing CVE
    It MUST be tested that the CVE number is given.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_informative_missing_cwe():
    """
    6.3.4 Missing CWE
    It MUST be tested that the CWE is given.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_informative_use_of_short_hash():
    """
    6.3.5 Use of Short Hash
    It MUST be tested that the length of the hash value is not shorter than 64 characters.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_informative_use_of_non_self_referencing_urls_failing_to_resolve():
    """
    6.3.6 Use of non-self referencing URLs Failing to Resolve
    For each URL which is not in the category `self`, it MUST be tested that it
    resolves with a HTTP status code from the 2xx or 3xx class.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_informative_use_of_self_referencing_urls_failing_to_resolve():
    """
    6.3.7 Use of self referencing URLs Failing to Resolve
    For each item in an array of type references_t with the category `self`,
    it MUST be tested that the URL referenced resolves with a HTTP status code
    less than 400.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_informative_spell_check():
    """
    6.3.8 Spell check
    If the document language is given, it MUST be tested that a spell check for
    the given language does not find any mistakes.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_informative_branch_categories():
    """
    6.3.9 Branch Categories
    For each element of type full_product_name_t in /product_tree/branches,
    it MUST be tested that ancestor nodes along the path exist which use the
    following branch categories `vendor` -> `product_name` -> `product_version`.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_informative_usage_of_product_version_range():
    """
    6.3.10 Usage of Product Version Range
    For each element of type branches_t, it MUST be tested that the `category`
    is not `product_version_range`.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_informative_usage_of_v_as_version_indicator():
    """
    6.3.11 Usage of V as Version Indicator
    For each element of type branches_t with category of product_version,
    it MUST be tested that the value of `name` does not start with `v` or `V`.
    """
    pass
