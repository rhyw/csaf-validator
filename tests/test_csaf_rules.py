"""
Stub tests for CSAF 2.0 validation rules based on csaf-v2.0-os.md.
"""
import pytest

# ##################################################################
#  6.1 Mandatory Tests
# ##################################################################

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_missing_product_id_definition():
    """
    6.1.1 Missing Definition of Product ID
    For each element of type product_id_t that is not inside a full_product_name_t,
    it MUST be tested that the full_product_name_t element with the matching
    product_id exists.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_multiple_product_id_definitions():
    """
    6.1.2 Multiple Definition of Product ID
    For each product_id_t in full_product_name_t elements, it MUST be tested
    that the product_id was not already defined within the same document.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_circular_product_id_definition():
    """
    6.1.3 Circular Definition of Product ID
    For each new defined product_id_t in items of relationships, it MUST be
    tested that the product_id does not end up in a circle.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_missing_product_group_id_definition():
    """
    6.1.4 Missing Definition of Product Group ID
    For each element of type product_group_id_t that is not inside a product_group,
    it MUST be tested that the product_group element with the matching group_id exists.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_multiple_product_group_id_definitions():
    """
    6.1.5 Multiple Definition of Product Group ID
    For each product_group_id_t in product_group elements, it MUST be tested
    that the group_id was not already defined within the same document.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_contradicting_product_status():
    """
    6.1.6 Contradicting Product Status
    For each item in /vulnerabilities, it MUST be tested that the same Product ID
    is not a member of contradicting product status groups.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_multiple_scores_with_same_version_per_product():
    """
    6.1.7 Multiple Scores with same Version per Product
    For each item in /vulnerabilities, it MUST be tested that the same Product ID
    is not a member of more than one CVSS-Vectors with the same version.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_invalid_cvss():
    """
    6.1.8 Invalid CVSS
    It MUST be tested that the given CVSS object is valid according to the
    referenced schema.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_invalid_cvss_computation():
    """
    6.1.9 Invalid CVSS computation
    It MUST be tested that the given CVSS object has the values computed
    correctly according to the definition.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_inconsistent_cvss():
    """
    6.1.10 Inconsistent CVSS
    It MUST be tested that the given CVSS properties do not contradict the
    CVSS vector.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_cwe():
    """
    6.1.11 CWE
    It MUST be tested that given CWE exists and is valid.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_language():
    """
    6.1.12 Language
    For each element of type lang_t, it MUST be tested that the language
    code is valid and exists.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_purl():
    """
    6.1.13 PURL
    It MUST be tested that given PURL is valid.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_sorted_revision_history():
    """
    6.1.14 Sorted Revision History
    It MUST be tested that the value of `number` of items of the revision history
    are sorted ascending when the items are sorted ascending by `date`.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_translator():
    """
    6.1.15 Translator
    It MUST be tested that /document/source_lang is present and set if the value
    `translator` is used for /document/publisher/category.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_latest_document_version():
    """
    6.1.16 Latest Document Version
    It MUST be tested that document version has the same value as the `number`
    in the last item of Revision History when it is sorted ascending by `date`.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_document_status_draft():
    """
    6.1.17 Document Status Draft
    It MUST be tested that document status is `draft` if the document version
    is `0` or `0.y.z` or contains the pre-release part.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_released_revision_history():
    """
    6.1.18 Released Revision History
    It MUST be tested that no item of the revision history has a `number` of `0`
    or `0.y.z` when the document status is `final` or `interim`.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_revision_history_entries_for_prerelease_versions():
    """
    6.1.19 Revision History Entries for Pre-release Versions
    It MUST be tested that no item of the revision history has a `number` which
    includes pre-release information.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_non_draft_document_version():
    """
    6.1.20 Non-draft Document Version
    It MUST be tested that document version does not contain a pre-release part
    if the document status is `final` or `interim`.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_missing_item_in_revision_history():
    """
    6.1.21 Missing Item in Revision History
    It MUST be tested that items of the revision history do not omit a version
    number when the items are sorted ascending by `date`.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_multiple_definition_in_revision_history():
    """
    6.1.22 Multiple Definition in Revision History
    It MUST be tested that items of the revision history do not contain the same
    version number.
    """
    pass

@pytest.mark.skip(reason="Not implemented yet")
def test_mandatory_multiple_use_of_same_cve():
    """
    6.1.23 Multiple Use of Same CVE
    It MUST be tested that a CVE is not used in multiple vulnerability items.
    """
    pass

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

# ##################################################################
#  6.2 Optional Tests
# ##################################################################

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

# ##################################################################
#  6.3 Informative Tests
# ##################################################################

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
