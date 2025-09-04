# CSAF Validator

A tool to validate CSAF (Common Security Advisory Framework) files against the CSAF 2.0 schema.

## Installation

```bash
pip install .
```

## Usage

```bash
csaf-validator /path/to/your/csaf.json
```

You can also specify a schema version:

```bash
csaf-validator --schema-version 2.0 /path/to/your/csaf.json
```

## Development

Set up a virtual environment and install the development dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

Alternatively, you can use the Makefile target:

```bash
make test
```

Each time there is update, you may want to install before testing:

```bash
make install
```
