"""
Stub tests for CSAF 2.0 validation rules based on csaf-v2.0-os.md.
"""

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


@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_multiple_definition_in_involvements():
    """
    6.1.24 Multiple Definition in Involvements
    It MUST be tested that items of the list of involvements do not contain the
    same `party` regardless of its `status` more than once at any `date`.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_multiple_use_of_same_hash_algorithm():
    """
    6.1.25 Multiple Use of Same Hash Algorithm
    It MUST be tested that the same hash algorithm is not used multiple times
    in one item of hashes.
    """
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_prohibited_document_category_name():
    """
    6.1.26 Prohibited Document Category Name
    It MUST be tested that the document category is not equal to the (case
    insensitive) name of any other profile than "CSAF Base".
    """
    pass


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
