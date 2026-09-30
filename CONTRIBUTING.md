# Contributing

Issues and focused pull requests are welcome. Please:

- add fixture-based tests for parser, advisory, or output changes;
- keep OSV tests mocked and never execute code from a scanned project;
- document severity, exit-code, and format changes in the README;
- avoid committing private lockfiles, credentials, or generated reports.

Run the local checks before submitting:

```console
python -m pytest
```
