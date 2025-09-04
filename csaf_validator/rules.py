"""
Implementation of CSAF 2.0 validation rules.
"""

from enum import Enum


class Rule(Enum):
    MANDATORY_MISSING_PRODUCT_ID_DEFINITION = (
        "6.1.1 Missing Definition of Product ID",
        "For each element of type product_id_t that is not inside a full_product_name_t, it MUST be tested that the full_product_name_t element with the matching product_id exists."
    )


class ValidationError:
    def __init__(self, rule_name, message):
        self.rule = rule_name
        self.message = message

def get_all_product_ids(doc):
    """
    Recursively finds all defined product_ids within the `product_tree` section of a CSAF document.
    This function is a crucial part of ensuring that all 'product_id's referenced elsewhere
    in the document (e.g., in vulnerabilities, remediations, threats) are properly defined
    in `full_product_name_t` elements.

    It collects product IDs from:
    - `product_tree.full_product_names[]`
    - `product_tree.relationships[].full_product_name`
    - `product_tree.branches[]...product` (recursively)

    Args:
        doc (dict): The CSAF document as a dictionary.

    Returns:
        set: A set of all unique product IDs defined in the product_tree.
    """
    product_ids = set()
    if 'product_tree' not in doc:
        return product_ids

    product_tree = doc['product_tree']

    if 'full_product_names' in product_tree:
        for full_product_name in product_tree.get('full_product_names', []):
            if 'product_id' in full_product_name:
                product_ids.add(full_product_name['product_id'])

    if 'relationships' in product_tree:
        for relationship in product_tree.get('relationships', []):
            if 'full_product_name' in relationship and 'product_id' in relationship['full_product_name']:
                product_ids.add(relationship['full_product_name']['product_id'])

    def find_in_branches(branches):
        for branch in branches:
            if 'product' in branch and 'product_id' in branch['product']:
                product_ids.add(branch['product']['product_id'])
            if 'branches' in branch:
                find_in_branches(branch['branches'])

    if 'branches' in product_tree:
        find_in_branches(product_tree.get('branches', []))

    return product_ids

def check_mandatory_missing_product_id_definition(doc):
    """
    6.1.1 Missing Definition of Product ID
    For each element of type product_id_t that is not inside a full_product_name_t,
    it MUST be tested that the full_product_name_t element with the matching
    product_id exists.
    """
    defined_ids = get_all_product_ids(doc)
    referenced_ids = set()
    errors = []

    # Gather all referenced IDs
    if doc.get('product_tree'):
        for group in doc['product_tree'].get('product_groups', []):
            for product_id in group.get('product_ids', []):
                referenced_ids.add(product_id)
        for rel in doc['product_tree'].get('relationships', []):
            if 'product_reference' in rel:
                referenced_ids.add(rel['product_reference'])
            if 'relates_to_product_reference' in rel:
                referenced_ids.add(rel['relates_to_product_reference'])

    for vuln in doc.get('vulnerabilities', []):
        if 'product_status' in vuln:
            for status_list in vuln['product_status'].values():
                for product_id in status_list:
                    referenced_ids.add(product_id)
        for remediation in vuln.get('remediations', []):
            for product_id in remediation.get('product_ids', []):
                referenced_ids.add(product_id)
        for score in vuln.get('scores', []):
            for product_id in score.get('products', []):
                referenced_ids.add(product_id)
        for threat in vuln.get('threats', []):
            for product_id in threat.get('product_ids', []):
                referenced_ids.add(product_id)
        for flag in vuln.get('flags', []):
            for product_id in flag.get('product_ids', []):
                referenced_ids.add(product_id)

    # Check for missing definitions
    missing_ids = referenced_ids - defined_ids
    for missing_id in missing_ids:
        errors.append(ValidationError(
            Rule.MANDATORY_MISSING_PRODUCT_ID_DEFINITION.name,
            f"Referenced product_id '{missing_id}' is not defined in the product_tree."
        ))

    return errors
