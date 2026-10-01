# lockwatch

[![Release](https://img.shields.io/github/v/release/Secx1/lockwatch?display_name=tag)](https://github.com/Secx1/lockwatch/releases)
[![License](https://img.shields.io/github/license/Secx1/lockwatch)](LICENSE)
[![Stars](https://img.shields.io/github/stars/Secx1/lockwatch?style=flat)](https://github.com/Secx1/lockwatch/stargazers)

lockwatch is a small, read-only dependency vulnerability scanner. It reads
`package-lock.json` (npm lockfile v1-v3), `requirements.txt`, and
`poetry.lock`, then optionally asks [OSV.dev](https://osv.dev/) about exact
versions. It never imports, installs, builds, or executes code from the
scanned project.

**Research track:** vulnerability research and disclosure plus security tool
development. Findings are version matches for review, not proof of exploitability
or runtime reachability.

## At a glance

| Concern | Behavior |
| --- | --- |
| Input | `package-lock.json` (v1–v3), `requirements.txt`, or `poetry.lock` |
| Network | Offline by default; `--osv` explicitly enables OSV.dev requests |
| Output | Text for review, JSON for automation, or SARIF for code-scanning systems |
| Execution | Reads lockfiles only; never imports, installs, builds, or runs project code |

## Review workflow

1. Pin dependencies and keep the lockfile in the same review scope as the
   source change.
2. Run an offline scan first and preserve the report as a CI artifact.
3. If policy permits, rerun with `--osv` using a bounded timeout and a reviewed
   cache; verify advisory details against the upstream source.
4. Confirm reachability and remediation in the owning project, then rescan the
   updated lockfile before release.

## Authorization and safe use

Only scan source trees and lockfiles that you are authorised to inspect. The
default mode is offline and makes no network requests. `--osv` explicitly
enables POST requests to the configured OSV endpoint; set `--timeout` and use
`--cache` when running in CI. The cache contains vulnerability responses and
should be treated as untrusted build output. No project code is evaluated.

```console
python -m pip install -e .
lockwatch scan package-lock.json --format sarif --severity-threshold high
lockwatch --requirements requirements.txt --osv --cache .lockwatch-cache.json --format json --pretty
```

`--severity-threshold` filters the report. Add `--fail-on high` to return exit
status 1 when a high-or-more-severe finding is present. JSON and SARIF reports
are intended for CI ingestion; text is convenient for a terminal. A report
can be written with `--output report.sarif`.

## Result limitations

OSV data and package metadata can be incomplete, delayed, or incorrect, and a
network timeout is reported as an error rather than treated as a clean scan.
Requirements without an exact pinned version are listed but cannot be queried
reliably. A finding means that OSV matched the recorded version; it is not proof
that the vulnerable code is reachable at runtime. Conversely, the absence of a
finding is not a guarantee of safety. Review advisories, transitive dependency
resolution, source provenance, and your own deployment context before making a
release decision.

## Development

```console
python -m pip install -e ".[dev]"
python -m pytest
```

Tests use local fixtures and mocked OSV responses. They do not require network
access or a target project's code.

## License

MIT

See `LICENSE` for the full text.
