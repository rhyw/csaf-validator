# CSAF Validator

A tool to validate CSAF (Common Security Advisory Framework) files against the CSAF 2.0 schema.

## Installation

```bash
uv pip install .
```

## Usage

Validate a CSAF file:

```bash
csaf-validator /path/to/your/csaf.json
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
pytest
```

Alternatively, use the Makefile:

```bash
make test
```
