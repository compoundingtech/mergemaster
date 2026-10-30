# mergemaster

Portable signed gate observations stored in immutable Git notes.

## Build and test

```sh
nix build
nix flake check
```

The flake provides the `mergemaster` binary and runs the Rust unit and Git
integration tests (`checks.evidence`) and copied script self-tests
(`checks.scripts`) on `x86_64-linux` and `aarch64-linux`. The development shell
provides both suites' Python, Git, OpenSSH and GNU command-line dependencies.

For development:

```sh
nix develop
cargo test --workspace
cargo run -- evidence --help
```

## Copied evidence scripts

The evidence scripts and their self-tests are copied byte-for-byte from
`compoundingtech/fractal` commit
`e83871ec919f95b3b3e2a9a1cd211c2ac37babda`. Their original Fractal configuration
paths, command names and defaults are intentionally unchanged; this extraction
does not make the scripts general-purpose replacements for the Rust CLI.
The accompanying systemd service and timer files are shipped as source only:
the flake does not install, enable or run them.

Run the script suite independently:

```sh
nix develop -c bash scripts/test-scripts
# Or, with dependencies and MERGEMASTER_EFFECT_UTILS already set:
bash scripts/test-scripts
```

`scripts/test-scripts` discovers every copied `scripts/*-test` self-test,
including `evidence-verify-test`; `st-test` and `fractal-test` are production
entrypoints, not self-tests. Fixture-only tests are not added to the suite.
The runner creates a temporary Git repository, restores
`tests/fixtures/fractal/` at the original repository-relative paths, then
overlays the current copied scripts and commits the combined tree. Tests that
read policy, workflows, source paths or Git objects therefore see the original
layout without modifying this checkout or evaluating the fixture's flake.
These fixture files remain test data, not active mergemaster policy.
The workflow-generation self-test also uses the original pinned `effect-utils`
source and its real `genie` binary. The flake supplies both; outside the
development shell, `MERGEMASTER_EFFECT_UTILS` must point to that pinned source.
The Nix check follows Fractal's bubblewrap setup: a network-isolated root
provides `/usr/bin/env` and `/bin/sh` for unmodified executable fixtures and
Git hooks created by the tests. An immutable test tool profile also supplies
the fixed system path that `st-test` intentionally gives child commands.


The original `script-test-supervisor` and its Python dependencies own fixture
process cleanup on Linux; the original `git-env-clean` removes inherited
repository selectors, and `ci-parallel-tests` collects failures across the
suite. The runner also isolates home/config/state directories and disables
inherited Git configuration. It removes its temporary repository on exit.
`GENIE_FRESHNESS_JOBS` controls parallelism (default 6).
Failed-test logs are retained under
`${XDG_CACHE_HOME:-$HOME/.cache}/mergemaster-script-tests`, or the directory
specified by `CI_PARALLEL_TESTS_KEEP`; in a Nix check they live in the build's
temporary directory. The suite needs no network service or running daemon.

## Evidence CLI

`mergemaster evidence` exposes `put`, `show`, `verify`, and the protected
`observe-ci` observer. It preserves the record format, notes refs, trust rules,
and configuration discovery of the extracted Fractal evidence implementation.
No daemon is required. Trust is supplied explicitly using an OpenSSH
allowed-signers file, not inferred from repository policy.

```sh
mergemaster evidence show --repo . --record "$RECORD"
mergemaster evidence verify --repo . --record "$RECORD" \
  --trusted-signers "$ALLOWED_SIGNERS"
```

The Rust evidence sources originate from `compoundingtech/fractal` commit
`d6e91e3b6db855c30b4d35f2e78a29a3948b1ded`. The evidence library is available as
`mergemaster_evidence::evidence`.