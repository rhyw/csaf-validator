"""Main entry point for the CSAF validator CLI."""

import argparse
import os
from csaf_validator.validator import Validator, ValidationError


def main():
    """Main function for the CSAF validator."""
    parser = argparse.ArgumentParser(description="Validate CSAF files.")
    parser.add_argument("file", help="Path to the CSAF file to validate.")
    parser.add_argument(
        "--schema-version",
        default="2.0",
        help="CSAF schema version to use for validation (e.g., '2.0', '2.1').",
    )
    args = parser.parse_args()

    print(f"Validating {args.file} with schema version {args.schema_version}...")

    # Construct the schema file path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    schema_file_name = f"csaf_{args.schema_version}.json"
    schema_file_path = os.path.join(current_dir, "schemas", schema_file_name)

    if not os.path.exists(schema_file_path):
        print(f"Error: Schema file not found for version {args.schema_version}: {schema_file_path}")
        exit(1)

    validator = Validator(schema_file_path)
    result = validator.validate(args.file)

    if result.is_valid:
        print("Validation successful.")
    else:
        print("Validation failed with the following errors:")
        for error in result.errors:
            print(f"- [{error.rule}] {error.message}")
        exit(1)


if __name__ == "__main__":
    main()
