"""
Implementation of CSAF 2.0 validation rules.
"""

from enum import Enum


class Rule(Enum):
    MANDATORY_MISSING_PRODUCT_ID_DEFINITION = (
        "6.1.1 Missing Definition of Product ID",
        "For each element of type product_id_t that is not inside a "
        "full_product_name_t, it MUST be tested that the full_product_name_t "
        "element with the matching product_id exists.",
    )
    MANDATORY_MULTIPLE_PRODUCT_ID_DEFINITIONS = (
        "6.1.2 Multiple Definition of Product ID",
        "For each product_id_t in full_product_name_t elements, it MUST be "
        "tested that the product_id was not already defined within the same "
        "document.",
    )
    MANDATORY_CIRCULAR_DEFINITION_OF_PRODUCT_ID = (
        "6.1.3 Circular Definition of Product ID",
        "For each new defined product_id_t in items of relationships, it MUST "
        "be tested that the product_id does not end up in a circle.",
    )


class ValidationError:
    def __init__(self, rule_name, message):
        self.rule = rule_name
        self.message = message


def get_all_product_ids(doc):
    """
    Recursively finds all defined product_ids within the `product_tree` section
    of a CSAF document. This function is a crucial part of ensuring that all
    'product_id's referenced elsewhere in the document (e.g., in
    vulnerabilities, remediations, threats) are properly defined in
    `full_product_name_t` elements.

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
    if "product_tree" not in doc:
        return product_ids

    product_tree = doc["product_tree"]

    if "full_product_names" in product_tree:
        for full_product_name in product_tree.get("full_product_names", []):
            if "product_id" in full_product_name:
                product_ids.add(full_product_name["product_id"])

    if "relationships" in product_tree:
        for relationship in product_tree.get("relationships", []):
            if (
                "full_product_name" in relationship
                and "product_id" in relationship["full_product_name"]
            ):
                product_ids.add(relationship["full_product_name"]["product_id"])

    def find_in_branches(branches):
        for branch in branches:
            if "product" in branch and "product_id" in branch["product"]:
                product_ids.add(branch["product"]["product_id"])
            if "branches" in branch:
                find_in_branches(branch["branches"])

    if "branches" in product_tree:
        find_in_branches(product_tree.get("branches", []))

    return product_ids


def check_mandatory_missing_product_id_definition(doc):
    """
    6.1.1 Missing Definition of Product ID
    For each element of type product_id_t that is not inside a
    full_product_name_t,
    it MUST be tested that the full_product_name_t element with the matching
    product_id exists.
    """
    defined_ids = get_all_product_ids(doc)
    referenced_ids = set()
    errors = []

    # Gather all referenced IDs
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

    # Check for missing definitions
    missing_ids = referenced_ids - defined_ids
    for missing_id in missing_ids:
        errors.append(
            ValidationError(
                Rule.MANDATORY_MISSING_PRODUCT_ID_DEFINITION.name,
                f"Referenced product_id '{missing_id}' is not defined in "
                "the product_tree.",
            )
        )

    return errors


def check_mandatory_multiple_product_id_definitions(doc):
    """
    6.1.2 Multiple Definition of Product ID
    For each product_id_t in full_product_name_t elements, it MUST be tested
    that the product_id was not already defined within the same document.
    """
    defined_ids = set()
    errors = []

    if "product_tree" not in doc:
        return errors

    product_tree = doc["product_tree"]

    # Check in full_product_names
    for full_product_name in product_tree.get("full_product_names", []):
        if "product_id" in full_product_name:
            product_id = full_product_name["product_id"]
            if product_id in defined_ids:
                errors.append(
                    ValidationError(
                        Rule.MANDATORY_MULTIPLE_PRODUCT_ID_DEFINITIONS.name,
                        f"Product ID '{product_id}' is defined multiple times "
                        "in full_product_names.",
                    )
                )
            defined_ids.add(product_id)

    # Check in relationships
    for relationship in product_tree.get("relationships", []):
        if (
            "full_product_name" in relationship
            and "product_id" in relationship["full_product_name"]
        ):
            product_id = relationship["full_product_name"]["product_id"]
            if product_id in defined_ids:
                errors.append(
                    ValidationError(
                        Rule.MANDATORY_MULTIPLE_PRODUCT_ID_DEFINITIONS.name,
                        f"Product ID '{product_id}' is defined multiple times "
                        "in relationships.",
                    )
                )
            defined_ids.add(product_id)

    # Check in branches (recursively)
    def find_duplicates_in_branches(branches):
        for branch in branches:
            if "product" in branch and "product_id" in branch["product"]:
                product_id = branch["product"]["product_id"]
                if product_id in defined_ids:
                    errors.append(
                        ValidationError(
                            Rule.MANDATORY_MULTIPLE_PRODUCT_ID_DEFINITIONS.name,
                            f"Product ID '{product_id}' is defined multiple "
                            "times in product_tree.branches.",
                        )
                    )
                defined_ids.add(product_id)
            if "branches" in branch:
                find_duplicates_in_branches(branch["branches"])

    if "branches" in product_tree:
        find_duplicates_in_branches(product_tree.get("branches", []))

    return errors


def check_mandatory_circular_definition_of_product_id(doc):
    """
    6.1.3 Circular Definition of Product ID
    For each new defined product_id_t in items of relationships, it MUST be
    tested that the product_id does not end up in a circle.
    """
    errors = []
    if "product_tree" not in doc or "relationships" not in doc["product_tree"]:
        return errors

    relationships = doc["product_tree"].get("relationships", [])

    adj = {}
    for rel in relationships:
        pid = rel.get("full_product_name", {}).get("product_id")
        if not pid:
            continue

        if pid not in adj:
            adj[pid] = []

        if "product_reference" in rel:
            adj[pid].append(rel["product_reference"])
        if "relates_to_product_reference" in rel:
            adj[pid].append(rel["relates_to_product_reference"])

    # `visiting` is for nodes currently in the recursion stack.
    # `visited` is for nodes that have been completely explored.
    visiting = set()
    visited = set()

    def has_cycle(node):
        visiting.add(node)

        for neighbor in adj.get(node, []):
            if neighbor in visiting:
                errors.append(
                    ValidationError(
                        Rule.MANDATORY_CIRCULAR_DEFINITION_OF_PRODUCT_ID.name,
                        f"Circular dependency detected for product_id '{neighbor}'",
                    )
                )
                return True
            if neighbor not in visited:
                if has_cycle(neighbor):
                    return True

        visiting.remove(node)
        visited.add(node)
        return False

    all_nodes = set(adj.keys())
    for deps in adj.values():
        all_nodes.update(deps)

    for node in all_nodes:
        if node not in visited:
            if has_cycle(node):
                # Found a cycle, but continue checking other components
                pass

    # Remove duplicate errors
    unique_errors = []
    seen_messages = set()
    for error in errors:
        if error.message not in seen_messages:
            unique_errors.append(error)
            seen_messages.add(error.message)

    return unique_errors
