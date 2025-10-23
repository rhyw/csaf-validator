# CSAF Validator

A tool to validate CSAF (Common Security Advisory Framework) files against the CSAF 2.0 schema.

## Installation

```bash
uv pip install .
```

## Usage

Validate a CSAF file:

```bash
uv run csaf-validator /path/to/your/csaf.json
```

Specify a schema version (e.g., 2.0):

```bash
csaf-validator --schema-version 2.0 /path/to/your/csaf.json
```

### Validating Sample Files

To validate sample CSAF JSON files, place them in the `csaf_validator/samples/` directory and run:

```bash
make validate
```

## Development

Set up your development environment:

```bash
uv venv .venv
source .venv/bin/activate
uv pip install -e .
```

### Running Tests

```bash
uv run pytest
```

Alternatively, use the Makefile:

```bash
make test
```

### Maintaining Dependencies

This project uses `uv` for dependency management, with `requirements.txt` ensuring reproducible builds.

To update dependencies (e.g., when a new version of a package is needed):

1.  **Update `pyproject.toml`**: Modify the version specifier for the desired package.
2.  **Generate `requirements.txt`**: Run `uv pip compile pyproject.toml -o requirements.txt` to re-generate the lock file based on `pyproject.toml`.
3.  **Sync environment**: Run `uv pip sync requirements.txt` to install the updated dependencies into your virtual environment.
4.  **Commit changes**: Commit both `pyproject.toml` and `requirements.txt` to version control.
