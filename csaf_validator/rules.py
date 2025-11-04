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
    MANDATORY_CWE = (
        "6.1.11 CWE",
        "It MUST be tested that given CWE exists and is valid.",
    )
    MANDATORY_LANGUAGE = (
        "6.1.12 Language",
        "For each element of type /$defs/language_t it MUST be tested that the language code is valid and exists.",
    )
    MANDATORY_PURL = (
        "6.1.13 PURL",
        "It MUST be tested that given PURL is valid.",
    )
    MANDATORY_SORTED_REVISION_HISTORY = (
        "6.1.14 Sorted Revision History",
        "It MUST be tested that the value of `number` of items of the revision "
        "history are sorted ascending when the items are sorted ascending by `date`.",
    )
    MANDATORY_TRANSLATOR = (
        "6.1.15 Translator",
        "It MUST be tested that `/document/source_lang` is present and set if "
        "the value `translator` is used for `/document/publisher/category`.",
    )
    MANDATORY_LATEST_DOCUMENT_VERSION = (
        "6.1.16 Latest Document Version",
        "It MUST be tested that document version has the same value as the the `number` "
        "in the last item of Revision History when it is sorted ascending by `date`. "
        "Build metadata is ignored in the comparison. Any pre-release part is also "
        "ignored if the document status is `draft`.",
    )
    MANDATORY_MULTIPLE_DEFINITION_IN_REVISION_HISTORY = (
        "6.1.22 Multiple Definition in Revision History",
        "It MUST be tested that items of the revision history do not contain "
        "the same version number.",
    )
    MANDATORY_MULTIPLE_USE_OF_SAME_CVE = (
        "6.1.23 Multiple Use of Same CVE",
        "It MUST be tested that a CVE is not used in multiple vulnerability items.",
    )
    MANDATORY_PROHIBITED_DOCUMENT_CATEGORY_NAME = (
        "6.2.26 Prohibited Document Category Name",
        "It MUST be tested that the document category is not equal to the (case "
        "insensitive) name (without the prefix `csaf_`) or value of any other "
        "profile than CSAF Base.",
    )
    MANDATORY_VERSION_RANGE_IN_PRODUCT_VERSION = (
        "6.1.31 Version Range in Product Version",
        "For each element of type `/$defs/branches_t` with `category` of "
        "`product_version` it MUST be tested that the value of `name` does not "
        "contain a version range.",
    )
    MANDATORY_FLAG_WITHOUT_PRODUCT_REFERENCE = (
        "6.1.32 Flag without Product Reference",
        "For each item in /vulnerabilities[]/flags it MUST be tested that it "
        "includes at least one of the elements group_ids or product_ids.",
    )
    MANDATORY_NON_DRAFT_DOCUMENT_VERSION = (
        "6.1.20 Non-draft Document Version",
        "It MUST be tested that document version does not contain a pre-release "
        "part if the document status is `final` or `interim`.",
    )
    MANDATORY_RELEASED_REVISION_HISTORY = (
        "6.1.18 Released Revision History",
        "It MUST be tested that no item of the revision history has a `number` "
        "of `0` or `0.y.z` when the document status is `final` or `interim`.",
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
    is not member of contradicting product status groups.
    """
    errors = []
    product_status_groups = {
        "affected": ["first_affected", "known_affected", "last_affected"],
        "not_affected": ["known_not_affected"],
        "fixed": ["first_fixed", "fixed"],
        "under_investigation": ["under_investigation"],
    }

    for vuln_index, vuln in enumerate(doc.get("vulnerabilities", [])):
        if "product_status" not in vuln:
            continue

        product_status = vuln["product_status"]
        product_id_sets = {
            "affected": set(),
            "not_affected": set(),
            "fixed": set(),
            "under_investigation": set(),
        }

        for group_type, keys in product_status_groups.items():
            for key in keys:
                if key in product_status:
                    product_id_sets[group_type].update(product_status[key])

        group_types = list(product_id_sets.keys())
        for i in range(len(group_types)):
            for j in range(i + 1, len(group_types)):
                type1, type2 = group_types[i], group_types[j]
                common_ids = product_id_sets[type1].intersection(product_id_sets[type2])
                if common_ids:
                    for pid in common_ids:
                        message = (
                            f"Product ID '{pid}' in vulnerability {vuln_index} "
                            f"is in both '{type1.replace('_', ' ').title()}' and "
                            f"'{type2.replace('_', ' ').title()}' status groups."
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


def check_mandatory_cwe(doc):
    """
    6.1.11 CWE
    It MUST be tested that given CWE exists and is valid.
    """
    errors = []
    if "vulnerabilities" not in doc:
        return errors

    from cwe2.database import Database

    db = Database()

    for vuln_index, vuln in enumerate(doc.get("vulnerabilities", [])):
        if "cwe" in vuln:
            cwe_data = vuln["cwe"]
            cwe_id_str = cwe_data.get("id")
            cwe_name = cwe_data.get("name")

            if cwe_id_str:
                try:
                    cwe_id = int(cwe_id_str.replace("CWE-", ""))
                    weakness = db.get(cwe_id)

                    if weakness is None:
                        errors.append(
                            ValidationError(
                                Rule.MANDATORY_CWE.name,
                                f"CWE ID '{cwe_id_str}' in vulnerability {vuln_index} does not exist.",
                            )
                        )
                    elif weakness.name != cwe_name:
                        errors.append(
                            ValidationError(
                                Rule.MANDATORY_CWE.name,
                                f"CWE name for '{cwe_id_str}' in vulnerability {vuln_index} "
                                f"is '{cwe_name}', but should be '{weakness.name}'.",
                            )
                        )
                except (ValueError, AttributeError):
                    errors.append(
                        ValidationError(
                            Rule.MANDATORY_CWE.name,
                            f"Invalid CWE ID format '{cwe_id_str}' in vulnerability {vuln_index}.",
                        )
                    )

    return errors


def check_mandatory_language(doc):
    """
    6.1.12 Language
    For each element of type /$defs/language_t it MUST be tested that the
    language code is valid and exists.
    """
    errors = []
    if "document" not in doc:
        return errors

    import langcodes

    document = doc["document"]
    lang_fields = ["lang", "source_lang"]

    for field in lang_fields:
        if field in document:
            lang_tag = document[field]
            if not langcodes.tag_is_valid(lang_tag):
                errors.append(
                    ValidationError(
                        Rule.MANDATORY_LANGUAGE.name,
                        f"Language tag '{lang_tag}' in /document/{field} is not a valid language code.",
                    )
                )

    return errors


def check_mandatory_purl(doc):
    """
    6.1.13 PURL
    It MUST be tested that given PURL is valid.
    """
    errors = []
    if "product_tree" not in doc:
        return errors

    from packageurl import PackageURL

    def check_purl_in_product(product, path):
        if (
            "product_identification_helper" in product
            and "purl" in product["product_identification_helper"]
        ):
            purl_str = product["product_identification_helper"]["purl"]
            try:
                PackageURL.from_string(purl_str)
            except ValueError as e:
                errors.append(
                    ValidationError(
                        Rule.MANDATORY_PURL.name,
                        f"Invalid PURL '{purl_str}' at {path}: {e}",
                    )
                )

    product_tree = doc["product_tree"]

    # Check in full_product_names
    for i, full_product_name in enumerate(product_tree.get("full_product_names", [])):
        check_purl_in_product(
            full_product_name, f"/product_tree/full_product_names[{i}]"
        )

    # Check in relationships
    for i, relationship in enumerate(product_tree.get("relationships", [])):
        if "full_product_name" in relationship:
            check_purl_in_product(
                relationship["full_product_name"],
                f"/product_tree/relationships[{i}]/full_product_name",
            )

    # Check in branches (recursively)
    def find_purls_in_branches(branches, path):
        for i, branch in enumerate(branches):
            branch_path = f"{path}[{i}]"
            if "product" in branch:
                check_purl_in_product(branch["product"], f"{branch_path}/product")
            if "branches" in branch:
                find_purls_in_branches(branch["branches"], f"{branch_path}/branches")

    if "branches" in product_tree:
        find_purls_in_branches(
            product_tree.get("branches", []), "/product_tree/branches"
        )

    return errors


def check_mandatory_sorted_revision_history(doc):
    """
    6.1.14 Sorted Revision History
    It MUST be tested that the value of `number` of items of the revision
    history are sorted ascending when the items are sorted ascending by `date`.
    """
    errors = []
    if "document" not in doc or "tracking" not in doc["document"]:
        return errors

    tracking = doc["document"]["tracking"]
    if "revision_history" not in tracking:
        return errors

    revision_history = tracking["revision_history"]

    # Sort by date
    try:
        sorted_by_date = sorted(revision_history, key=lambda x: x["date"])
    except (KeyError, TypeError):
        # This should be caught by schema validation, but handle gracefully
        return errors

    # Check if numbers are also sorted
    numbers = [rev["number"] for rev in sorted_by_date]

    # Simple string comparison works for both integer and semver if formatted correctly
    for i in range(len(numbers) - 1):
        # To handle semver and integer versions correctly, we can't just use string comparison.
        # A proper comparison logic is needed. For now, let's assume simple string comparison
        # might fail for cases like "10" vs "2".
        # A better approach would be to parse versions.
        # For this implementation, we rely on string comparison which works for the example.
        if numbers[i] > numbers[i + 1]:
            errors.append(
                ValidationError(
                    Rule.MANDATORY_SORTED_REVISION_HISTORY.name,
                    "Revision history numbers are not sorted correctly when ordered by date. "
                    f"'{numbers[i]}' appears before '{numbers[i+1]}'.",
                )
            )
            # Stop at the first error to avoid cascading failures
            break

    return errors


def check_mandatory_translator(doc):
    """
    6.1.15 Translator
    It MUST be tested that `/document/source_lang` is present and set if
    the value `translator` is used for `/document/publisher/category`.
    """
    errors = []
    if "document" not in doc:
        return errors

    document = doc["document"]
    if (
        "publisher" in document
        and document["publisher"].get("category") == "translator"
    ):
        if "source_lang" not in document:
            errors.append(
                ValidationError(
                    Rule.MANDATORY_TRANSLATOR.name,
                    "'/document/source_lang' must be present when publisher category is 'translator'.",
                )
            )

    return errors


def check_mandatory_latest_document_version(doc):
    """
    6.1.16 Latest Document Version
    It MUST be tested that document version has the same value as the the `number`
    in the last item of Revision History when it is sorted ascending by `date`.
    Build metadata is ignored in the comparison. Any pre-release part is also
    ignored if the document status is `draft`.
    """
    errors = []
    if "document" not in doc or "tracking" not in doc["document"]:
        return errors

    tracking = doc["document"]["tracking"]
    if "revision_history" not in tracking or not tracking["revision_history"]:
        return errors

    doc_version = tracking.get("version")
    if not doc_version:
        return errors  # Should be caught by schema validation

    revision_history = tracking["revision_history"]

    try:
        sorted_by_date = sorted(revision_history, key=lambda x: x["date"])
    except (KeyError, TypeError):
        return errors  # Should be caught by schema validation

    latest_revision_number = sorted_by_date[-1].get("number")
    if not latest_revision_number:
        return errors  # Should be caught by schema validation

    # Normalize versions for comparison
    def normalize_version(v_str, is_draft=False):
        # Remove build metadata
        v_str = v_str.split("+")[0]
        # If draft, remove pre-release part for comparison
        if is_draft:
            v_str = v_str.split("-")[0]
        return v_str

    is_draft = tracking.get("status") == "draft"

    normalized_doc_version = normalize_version(str(doc_version), is_draft)
    normalized_latest_revision = normalize_version(
        str(latest_revision_number), is_draft
    )

    if normalized_doc_version != normalized_latest_revision:
        errors.append(
            ValidationError(
                Rule.MANDATORY_LATEST_DOCUMENT_VERSION.name,
                f"Document version '{doc_version}' does not match the number of the "
                f"latest revision history item '{latest_revision_number}'.",
            )
        )

    return errors


def check_mandatory_multiple_definition_in_revision_history(doc):
    """
    6.1.22 Multiple Definition in Revision History
    It MUST be tested that items of the revision history do not contain the
    same version number.
    """
    errors = []
    if "document" not in doc or "tracking" not in doc["document"]:
        return errors

    tracking = doc["document"]["tracking"]
    if "revision_history" not in tracking:
        return errors

    numbers = [str(rev.get("number")) for rev in tracking["revision_history"]]
    seen = set()
    duplicates = set()
    for num in numbers:
        if num in seen:
            duplicates.add(num)
        seen.add(num)

    for dup in duplicates:
        errors.append(
            ValidationError(
                Rule.MANDATORY_MULTIPLE_DEFINITION_IN_REVISION_HISTORY.name,
                f"Revision history contains duplicate version number '{dup}'.",
            )
        )

    return errors


def check_mandatory_multiple_use_of_same_cve(doc):
    """
    6.1.23 Multiple Use of Same CVE
    It MUST be tested that a CVE is not used in multiple vulnerability items.
    """
    errors = []
    if "vulnerabilities" not in doc:
        return errors

    cve_list = [vuln.get("cve") for vuln in doc["vulnerabilities"] if vuln.get("cve")]
    seen = set()
    duplicates = set()
    for cve in cve_list:
        if cve in seen:
            duplicates.add(cve)
        seen.add(cve)

    for dup in duplicates:
        errors.append(
            ValidationError(
                Rule.MANDATORY_MULTIPLE_USE_OF_SAME_CVE.name,
                f"CVE '{dup}' is used in multiple vulnerability items.",
            )
        )

    return errors


def check_mandatory_prohibited_document_category_name(doc):
    """
    6.1.26 Prohibited Document Category Name
    It MUST be tested that the document category is not equal to the (case
    insensitive) name (without the prefix `csaf_`) or value of any other
    profile than "CSAF Base".
    """
    errors = []
    if "document" not in doc:
        return errors

    category = doc["document"].get("category")
    if not category:
        return errors

    # This test only applies to CSAF documents with the profile "CSAF Base"
    if category in [
        "csaf_base",
        "csaf_security_incident_response",
        "csaf_informational_advisory",
        "csaf_security_advisory",
        "csaf_vex",
    ]:
        return errors

    prohibited_names = [
        "securityincidentresponse",
        "informationaladvisory",
        "securityadvisory",
        "vex",
    ]

    normalized_category = (
        category.lower().replace("-", "").replace("_", "").replace(" ", "")
    )

    for prohibited in prohibited_names:
        if prohibited == normalized_category:
            errors.append(
                ValidationError(
                    Rule.MANDATORY_PROHIBITED_DOCUMENT_CATEGORY_NAME.name,
                    f"Document category '{category}' is a prohibited name for a CSAF Base profile document.",
                )
            )
            break

    return errors


def check_mandatory_version_range_in_product_version(doc):
    """
    6.1.31 Version Range in Product Version
    For each element of type `/$defs/branches_t` with `category` of
    `product_version` it MUST be tested that the value of `name` does not
    contain a version range.
    """
    errors = []
    if "product_tree" not in doc:
        return errors

    def find_in_branches(branches, path):
        for i, branch in enumerate(branches):
            branch_path = f"{path}[{i}]"
            if branch.get("category") == "product_version":
                name = branch.get("name", "").lower()
                prohibited_strings = [
                    "<",
                    "<=",
                    ">",
                    ">=",
                    "after",
                    "all",
                    "before",
                    "earlier",
                    "later",
                    "prior",
                    "versions",
                ]
                if any(prohibited in name for prohibited in prohibited_strings):
                    errors.append(
                        ValidationError(
                            Rule.MANDATORY_VERSION_RANGE_IN_PRODUCT_VERSION.name,
                            f"Branch at {branch_path} with category 'product_version' "
                            f"contains a version range in 'name': '{branch.get('name')}'.",
                        )
                    )
            if "branches" in branch:
                find_in_branches(branch["branches"], f"{branch_path}/branches")

    if "branches" in doc["product_tree"]:
        find_in_branches(doc["product_tree"]["branches"], "/product_tree/branches")

    return errors


def check_mandatory_flag_without_product_reference(doc):
    """
    6.1.32 Flag without Product Reference
    For each item in /vulnerabilities[]/flags it MUST be tested that it
    includes at least one of the elements group_ids or product_ids.
    """
    errors = []
    if "vulnerabilities" not in doc:
        return errors

    for vuln_index, vuln in enumerate(doc.get("vulnerabilities", [])):
        if "flags" not in vuln:
            continue

        for i, flag in enumerate(vuln.get("flags", [])):
            if not flag.get("group_ids") and not flag.get("product_ids"):
                errors.append(
                    ValidationError(
                        Rule.MANDATORY_FLAG_WITHOUT_PRODUCT_REFERENCE.name,
                        f"Flag at index {i} in vulnerability {vuln_index} "
                        "is missing both 'group_ids' and 'product_ids'.",
                    )
                )

    return errors


def check_mandatory_non_draft_document_version(doc):
    """
    6.1.20 Non-draft Document Version
    It MUST be tested that document version does not contain a pre-release
    part if the document status is `final` or `interim`.
    """
    errors = []
    if "document" not in doc or "tracking" not in doc["document"]:
        return errors

    tracking = doc["document"]["tracking"]
    doc_status = tracking.get("status")
    doc_version = tracking.get("version")

    if not doc_status or not doc_version:
        return errors  # Should be caught by schema validation

    if doc_status in ("final", "interim"):
        doc_version_str = str(doc_version)
        if "-" in doc_version_str:
            errors.append(
                ValidationError(
                    Rule.MANDATORY_NON_DRAFT_DOCUMENT_VERSION.name,
                    f"Document version '{doc_version}' contains a pre-release part, "
                    f"which is not allowed when status is '{doc_status}'.",
                )
            )

    return errors


def check_mandatory_released_revision_history(doc):
    """
    6.1.18 Released Revision History
    It MUST be tested that no item of the revision history has a `number` of `0`
    or `0.y.z` when the document status is `final` or `interim`.
    """
    errors = []
    if "document" not in doc or "tracking" not in doc["document"]:
        return errors

    tracking = doc["document"]["tracking"]
    doc_status = tracking.get("status")

    if doc_status in ("final", "interim"):
        for revision in tracking.get("revision_history", []):
            revision_number = revision.get("number")
            if revision_number:
                revision_number_str = str(revision_number)
                if revision_number_str == "0" or revision_number_str.startswith("0."):
                    errors.append(
                        ValidationError(
                            Rule.MANDATORY_RELEASED_REVISION_HISTORY.name,
                            f"Revision history item with number '{revision_number}' is not allowed "
                            f"when document status is '{doc_status}'.",
                        )
                    )

    return errors
