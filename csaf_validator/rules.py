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
    MANDATORY_MISSING_PRODUCT_GROUP_ID_DEFINITION = (
        "6.1.4 Missing Definition of Product Group ID",
        "For each element of type product_group_id_t that is not inside a "
        "product_group, it MUST be tested that the product_group element with "
        "the matching group_id exists.",
    )
    MANDATORY_MULTIPLE_DEFINITION_OF_PRODUCT_GROUP_ID = (
        "6.1.5 Multiple Definition of Product Group ID",
        "For each Product Group ID in Product Group elements, it MUST be tested "
        "that the group_id was not already defined within the same document.",
    )
    MANDATORY_CONTRADICTING_PRODUCT_STATUS = (
        "6.1.6 Contradicting Product Status",
        "For each item in /vulnerabilities it MUST be tested that the same "
        "Product ID is not member of contradicting product status groups.",
    )
    MANDATORY_MULTIPLE_SCORES_WITH_SAME_VERSION_PER_PRODUCT = (
        "6.1.7 Multiple Scores with same Version per Product",
        "For each item in /vulnerabilities it MUST be tested that the same "
        "Product ID is not member of more than one CVSS-Vectors with the same version.",
    )
    MANDATORY_INVALID_CVSS_COMPUTATION = (
        "6.1.9 Invalid CVSS computation",
        "It MUST be tested that the given CVSS object has the values computed "
        "correctly according to the definition.",
    )
    MANDATORY_INCONSISTENT_CVSS = (
        "6.1.10 Inconsistent CVSS",
        "It MUST be tested that the given CVSS properties do not contradict the CVSS vector.",
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


def get_all_product_group_ids(doc):
    """
    Collects all defined product_group_ids within the `product_tree.product_groups`
    section of a CSAF document.

    Args:
        doc (dict): The CSAF document as a dictionary.

    Returns:
        set: A set of all unique product group IDs defined in the product_tree.
    """
    product_group_ids = set()
    if "product_tree" not in doc:
        return product_group_ids

    product_tree = doc["product_tree"]

    if "product_groups" in product_tree:
        for group in product_tree.get("product_groups", []):
            if "group_id" in group:
                product_group_ids.add(group["group_id"])

    return product_group_ids


def check_mandatory_missing_product_group_id_definition(doc):
    """
    6.1.4 Missing Definition of Product Group ID
    For each element of type product_group_id_t that is not inside a product_group,
    it MUST be tested that the product_group element with the matching group_id exists.
    """
    defined_group_ids = get_all_product_group_ids(doc)
    referenced_group_ids = set()
    errors = []

    # Helper to collect product group IDs from lists
    def collect_group_ids(id_list):
        if isinstance(id_list, list):
            for group_id in id_list:
                referenced_group_ids.add(group_id)

    # Gather all referenced Product Group IDs
    for vuln in doc.get("vulnerabilities", []):
        for remediation in vuln.get("remediations", []):
            collect_group_ids(remediation.get("product_groups", []))
        for score in vuln.get("scores", []):
            collect_group_ids(score.get("product_groups", []))
        for threat in vuln.get("threats", []):
            collect_group_ids(threat.get("product_groups", []))
        for flag in vuln.get("flags", []):
            collect_group_ids(flag.get("product_groups", []))

    # Check for missing definitions
    missing_group_ids = referenced_group_ids - defined_group_ids
    if missing_group_ids:
        print(f"DEBUG: Missing product group IDs: {missing_group_ids}")
    for missing_id in missing_group_ids:
        errors.append(
            ValidationError(
                Rule.MANDATORY_MISSING_PRODUCT_GROUP_ID_DEFINITION.name,
                f"Referenced product_group_id '{missing_id}' is not defined in "
                "the product_tree.product_groups.",
            )
        )
    return errors


def check_mandatory_multiple_definition_of_product_group_id(doc):
    """
    6.1.5 Multiple Definition of Product Group ID
    For each Product Group ID (type /$defs/product_group_id_t) Product Group
    elements (/product_tree/product_groups[]) it MUST be tested that the
    group_id was not already defined within the same document.
    """
    defined_group_ids = set()
    errors = []

    if "product_tree" not in doc or "product_groups" not in doc["product_tree"]:
        return errors

    for group in doc["product_tree"].get("product_groups", []):
        if "group_id" in group:
            group_id = group["group_id"]
            print(
                f"DEBUG: Processing group_id: {group_id}, Current defined_group_ids: {defined_group_ids}"
            )
            if group_id in defined_group_ids:
                errors.append(
                    ValidationError(
                        Rule.MANDATORY_MULTIPLE_DEFINITION_OF_PRODUCT_GROUP_ID.name,
                        f"Product Group ID '{group_id}' is defined multiple times "
                        "in product_tree.product_groups.",
                    )
                )
            defined_group_ids.add(group_id)
    return errors


def check_mandatory_multiple_scores_with_same_version_per_product(doc):
    """
    6.1.7 Multiple Scores with same Version per Product
    For each item in /vulnerabilities it MUST be tested that the same Product ID
    is not member of more than one CVSS-Vectors with the same version.
    """
    errors = []
    if "vulnerabilities" not in doc:
        return errors

    for vuln_index, vuln in enumerate(doc.get("vulnerabilities", [])):
        if "scores" not in vuln:
            continue

        product_scores = {}  # Key: product_id, Value: set of cvss versions

        for score in vuln.get("scores", []):
            products = score.get("products", [])
            cvss_version = None
            if "cvss_v3" in score:
                cvss_version = score["cvss_v3"].get("version")
            elif "cvss_v2" in score:
                cvss_version = score["cvss_v2"].get("version")

            if cvss_version:
                for product_id in products:
                    if product_id not in product_scores:
                        product_scores[product_id] = set()

                    if cvss_version in product_scores[product_id]:
                        message = f"Product ID '{product_id}' has multiple scores for CVSS version {cvss_version}"
                        # To prevent duplicate errors for the same issue
                        if not any(
                            err.message == message
                            and err.rule
                            == Rule.MANDATORY_MULTIPLE_SCORES_WITH_SAME_VERSION_PER_PRODUCT.name
                            for err in errors
                        ):
                            errors.append(
                                ValidationError(
                                    Rule.MANDATORY_MULTIPLE_SCORES_WITH_SAME_VERSION_PER_PRODUCT.name,
                                    message,
                                )
                            )
                    else:
                        product_scores[product_id].add(cvss_version)

    return errors


def check_mandatory_contradicting_product_status(doc):
    """
    6.1.6 Contradicting Product Status
    For each item in /vulnerabilities it MUST be tested that the same Product ID
    is not member of contradicting product status groups. The sets formed by the
    contradicting groups within one vulnerability item MUST be pairwise disjoint.
    """
    errors = []
    if "vulnerabilities" not in doc:
        return errors

    contradiction_groups = {
        "affected": [
            "first_affected",
            "known_affected",
            "last_affected",
        ],
        "not_affected": ["known_not_affected"],
        "fixed": ["first_fixed", "fixed"],
        "under_investigation": ["under_investigation"],
    }

    for vuln_index, vuln in enumerate(doc["vulnerabilities"]):
        if "product_status" not in vuln:
            continue

        product_status = vuln["product_status"]
        product_id_sets = {
            "affected": set(),
            "not_affected": set(),
            "fixed": set(),
            "under_investigation": set(),
        }

        for group_type, status_keys in contradiction_groups.items():
            for key in status_keys:
                if key in product_status:
                    product_id_sets[group_type].update(product_status[key])

        # Check for pairwise disjoint sets
        if product_id_sets["affected"].intersection(product_id_sets["not_affected"]):
            common_ids = product_id_sets["affected"].intersection(
                product_id_sets["not_affected"]
            )
            for pid in common_ids:
                message = (
                    f"Product ID '{pid}' in vulnerability {vuln_index} "
                    "is in both 'Affected' and 'Not affected' status groups."
                )
                errors.append(
                    ValidationError(
                        Rule.MANDATORY_CONTRADICTING_PRODUCT_STATUS.name,
                        message,
                    )
                )

        if product_id_sets["affected"].intersection(product_id_sets["fixed"]):
            common_ids = product_id_sets["affected"].intersection(
                product_id_sets["fixed"]
            )
            for pid in common_ids:
                message = (
                    f"Product ID '{pid}' in vulnerability {vuln_index} is in both "
                    "'Affected' and 'Fixed' status groups."
                )
                errors.append(
                    ValidationError(
                        Rule.MANDATORY_CONTRADICTING_PRODUCT_STATUS.name,
                        message,
                    )
                )

        if product_id_sets["affected"].intersection(
            product_id_sets["under_investigation"]
        ):
            common_ids = product_id_sets["affected"].intersection(
                product_id_sets["under_investigation"]
            )
            for pid in common_ids:
                message = (
                    f"Product ID '{pid}' in vulnerability {vuln_index} is in both "
                    "'Affected' and 'Under investigation' status groups."
                )
                errors.append(
                    ValidationError(
                        Rule.MANDATORY_CONTRADICTING_PRODUCT_STATUS.name,
                        message,
                    )
                )

        if product_id_sets["not_affected"].intersection(product_id_sets["fixed"]):
            common_ids = product_id_sets["not_affected"].intersection(
                product_id_sets["fixed"]
            )
            for pid in common_ids:
                message = (
                    f"Product ID '{pid}' in vulnerability {vuln_index} is in both "
                    "'Not affected' and 'Fixed' status groups."
                )
                errors.append(
                    ValidationError(
                        Rule.MANDATORY_CONTRADICTING_PRODUCT_STATUS.name,
                        message,
                    )
                )

        if product_id_sets["not_affected"].intersection(
            product_id_sets["under_investigation"]
        ):
            common_ids = product_id_sets["not_affected"].intersection(
                product_id_sets["under_investigation"]
            )
            for pid in common_ids:
                message = (
                    f"Product ID '{pid}' in vulnerability {vuln_index} is in both "
                    "'Not affected' and 'Under investigation' status groups."
                )
                errors.append(
                    ValidationError(
                        Rule.MANDATORY_CONTRADICTING_PRODUCT_STATUS.name,
                        message,
                    )
                )

        if product_id_sets["fixed"].intersection(
            product_id_sets["under_investigation"]
        ):
            common_ids = product_id_sets["fixed"].intersection(
                product_id_sets["under_investigation"]
            )
            for pid in common_ids:
                message = (
                    f"Product ID '{pid}' in vulnerability {vuln_index} is in both "
                    "'Fixed' and 'Under investigation' status groups."
                )
                errors.append(
                    ValidationError(
                        Rule.MANDATORY_CONTRADICTING_PRODUCT_STATUS.name,
                        message,
                    )
                )

    return errors


def check_mandatory_invalid_cvss_computation(doc):
    """
    6.1.9 Invalid CVSS computation
    It MUST be tested that the given CVSS object has the values computed
    correctly according to the definition. The `vectorString` SHOULD take
    precedence.
    """
    errors = []
    if "vulnerabilities" not in doc:
        return errors

    for vuln_index, vuln in enumerate(doc.get("vulnerabilities", [])):
        if "scores" not in vuln:
            continue

        for score_index, score in enumerate(vuln.get("scores", [])):
            if "cvss_v3" in score:
                cvss_data = score["cvss_v3"]
                vector_string = cvss_data.get("vectorString")
                if vector_string:
                    try:
                        from cvss import CVSS3

                        # The library automatically handles 3.0 vs 3.1 from the vector string
                        c = CVSS3(vector_string)
                        computed_score = c.base_score
                        computed_severity = (
                            c.severities()[0] if hasattr(c, "severities") else "UNKNOWN"
                        )

                        if "baseScore" in cvss_data and float(
                            cvss_data["baseScore"]
                        ) != float(computed_score):
                            errors.append(
                                ValidationError(
                                    Rule.MANDATORY_INVALID_CVSS_COMPUTATION.name,
                                    f"CVSS v3.x baseScore in vulnerability {vuln_index}, score {score_index} "
                                    f"is {cvss_data['baseScore']}, but should be {computed_score} "
                                    f"based on vectorString '{vector_string}'.",
                                )
                            )
                        if (
                            "baseSeverity" in cvss_data
                            and hasattr(c, "severities")
                            and cvss_data["baseSeverity"].upper()
                            != computed_severity.upper()
                        ):
                            errors.append(
                                ValidationError(
                                    Rule.MANDATORY_INVALID_CVSS_COMPUTATION.name,
                                    f"CVSS v3.x baseSeverity in vulnerability {vuln_index}, score {score_index} "
                                    f"is '{cvss_data['baseSeverity']}', but should be '{computed_severity}' "
                                    f"based on vectorString '{vector_string}'.",
                                )
                            )
                    except Exception as e:
                        errors.append(
                            ValidationError(
                                Rule.MANDATORY_INVALID_CVSS_COMPUTATION.name,
                                f"Error parsing CVSS v3.x vectorString '{vector_string}' "
                                f"in vulnerability {vuln_index}, score {score_index}: {e}",
                            )
                        )

            if "cvss_v2" in score:
                cvss_data = score["cvss_v2"]
                vector_string = cvss_data.get("vectorString")
                if vector_string:
                    try:
                        from cvss import CVSS2

                        c = CVSS2(vector_string)
                        computed_score = c.base_score

                        if "baseScore" in cvss_data and float(
                            cvss_data["baseScore"]
                        ) != float(computed_score):
                            errors.append(
                                ValidationError(
                                    Rule.MANDATORY_INVALID_CVSS_COMPUTATION.name,
                                    f"CVSS v2.0 baseScore in vulnerability {vuln_index}, score {score_index} "
                                    f"is {cvss_data['baseScore']}, but should be {computed_score} "
                                    f"based on vectorString '{vector_string}'.",
                                )
                            )
                    except Exception as e:
                        errors.append(
                            ValidationError(
                                Rule.MANDATORY_INVALID_CVSS_COMPUTATION.name,
                                f"Error parsing CVSS v2.0 vectorString '{vector_string}' "
                                f"in vulnerability {vuln_index}, score {score_index}: {e}",
                            )
                        )

    return errors


def check_mandatory_inconsistent_cvss(doc):
    """
    6.1.10 Inconsistent CVSS
    It MUST be tested that the given CVSS properties do not contradict the CVSS vector.
    """
    errors = []
    if "vulnerabilities" not in doc:
        return errors

    for vuln_index, vuln in enumerate(doc.get("vulnerabilities", [])):
        if "scores" not in vuln:
            continue

        for score_index, score in enumerate(vuln.get("scores", [])):
            if "cvss_v3" in score:
                cvss_data = score["cvss_v3"]
                vector_string = cvss_data.get("vectorString")
                if vector_string:
                    try:
                        from cvss import CVSS3

                        c = CVSS3(vector_string)
                        metrics = c.metrics

                        for key, value in metrics.items():
                            if key in cvss_data and cvss_data[key] != value:
                                errors.append(
                                    ValidationError(
                                        Rule.MANDATORY_INCONSISTENT_CVSS.name,
                                        f"CVSS v3.x {key} in vulnerability {vuln_index}, score {score_index} "
                                        f"is '{cvss_data[key]}', but should be '{value}' "
                                        f"based on vectorString '{vector_string}'.",
                                    )
                                )
                    except Exception as e:
                        errors.append(
                            ValidationError(
                                Rule.MANDATORY_INCONSISTENT_CVSS.name,
                                f"Error parsing CVSS v3.x vectorString '{vector_string}' "
                                f"in vulnerability {vuln_index}, score {score_index}: {e}",
                            )
                        )
            if "cvss_v2" in score:
                cvss_data = score["cvss_v2"]
                vector_string = cvss_data.get("vectorString")
                if vector_string:
                    try:
                        from cvss import CVSS2

                        c = CVSS2(vector_string)
                        metrics = c.metrics

                        for key, value in metrics.items():
                            if key in cvss_data and cvss_data[key] != value:
                                errors.append(
                                    ValidationError(
                                        Rule.MANDATORY_INCONSISTENT_CVSS.name,
                                        f"CVSS v2.0 {key} in vulnerability {vuln_index}, score {score_index} "
                                        f"is '{cvss_data[key]}', but should be '{value}' "
                                        f"based on vectorString '{vector_string}'.",
                                    )
                                )
                    except Exception as e:
                        errors.append(
                            ValidationError(
                                Rule.MANDATORY_INCONSISTENT_CVSS.name,
                                f"Error parsing CVSS v2.0 vectorString '{vector_string}' "
                                f"in vulnerability {vuln_index}, score {score_index}: {e}",
                            )
                        )
    return errors
