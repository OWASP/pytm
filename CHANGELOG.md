# Changelog

All notable changes to pytm are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
This project follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)
in spirit, with one deliberate exception in 1.4.0 (see the BREAKING heading
below).

## [Unreleased]

## [1.4.0] - 2026-05-21

### BREAKING

- **Removed `tm.sqlDump()` and the `--sqldump` CLI flag (#295, #301).** Calls to
  `tm.sqlDump(...)` will raise `AttributeError` at runtime. There is no
  drop-in replacement; use `--json` for machine-readable output. This breakage
  is shipped in a minor release on the assumption of no real-world users; if
  this is wrong, please open an issue and we will publish a stub release.

### Added

- New `LLM` element class with eight associated threat definitions covering
  common LLM-specific attack patterns (#316).
- New LLM threat for untrusted tool launch configuration (#329).
- `likelihood` field on `Finding`, propagated from the originating `Threat` and
  overridable per-finding (#318).
- `flows` module providing helpers for declarative `Dataflow` construction
  (#259).
- `Data` object decoding in the JSON decoder, enabling round-trip serialization
  of `Data` instances (#330).
- Devcontainer configuration for VS Code / GitHub Codespaces (#307).
- Devbox setup with Poetry integration (#274, #282, #283, #289).
- Ruff linter configuration alongside Black (#325).
- Google-style docstrings on the `Actor` model entity (#311).
- ROADMAP entries for 2025 and beyond.

### Changed

- Internal element model refactored to Pydantic v2 (#320). The user-facing
  construction API in `tm.py`-style scripts is preserved: `Element(name)`,
  attribute assignment, and `controls.*` access continue to work as before.
  Pydantic v2 (`>=2.10`) is now a hard runtime dependency. Users with
  environments pinned to Pydantic v1 must upgrade.
- Minimum supported Python is now 3.11. Tested against 3.11, 3.12, 3.13, and
  3.14. Python 3.10 and earlier are no longer supported. Python 3.9 reached
  end-of-life in October 2025; 3.10 reaches end-of-life in October 2026.
- Migrated the test suite from `unittest` to `pytest` (#276). Existing
  invocations via `python -m unittest` are replaced by `pytest`; CI scripts
  updated accordingly.
- Upgraded the Docker base image to `python:3.14.4-alpine3.23` (#309).
- Updated Makefile and Dockerfile build pipeline (#321).
- Cleaned up legacy and unused files in the repository (#326).
- CODEOWNERS now defaults a maintainer set on all paths.

### Fixed

- `getInScopeFindings()` regression introduced by the Pydantic refactor (#323).
- `likelihood` regression on resolved findings, with regression tests added
  (#324).
- Findings on assets with `inScope=False` are now correctly suppressed (#312).
- CVSS and response overrides on `Finding` are no longer overwritten during
  threat resolution (#248).
- Various type annotation fixes and minor cleanups (#322).

### Security

- Escaped HTML metacharacters in DOT (Graphviz) output to prevent injection in
  rendered diagrams (#278, #280).

## [1.3.1] - prior

See [git history](https://github.com/OWASP/pytm/commits/v1.3.1) for releases
prior to 1.4.0. Earlier versions did not maintain a CHANGELOG; only 1.4.0 and
later are documented here.

[Unreleased]: https://github.com/OWASP/pytm/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/OWASP/pytm/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/OWASP/pytm/releases/tag/v1.3.1
