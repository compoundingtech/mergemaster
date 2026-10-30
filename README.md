# mergemaster

Portable signed gate observations stored in immutable Git notes.

## Build and test

```sh
nix build
nix flake check
```

The flake provides the `mergemaster` binary and runs the Rust unit and Git
integration tests (`checks.evidence`) on `x86_64-linux` and `aarch64-linux`.
CI runs the copied script self-tests as a separate
`nix develop -c bash scripts/test-scripts` step on both architectures.
The default development shell provides both suites' real tool dependencies
and pinned source inputs. Script tests run on the host, not inside a Nix
derivation or a nested bubblewrap sandbox.

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
# Or, with dependencies and both pinned-source environment variables set:
bash scripts/test-scripts
```

`scripts/test-scripts` discovers every copied `scripts/*-test` self-test,
including `evidence-verify-test`; `st-test` and `fractal-test` are production
entrypoints, not self-tests. Fixture-only tests are not added to the suite.
The runner creates a temporary Git repository using the immutable non-flake
`fractal-fixture` input, then overlays the small intentional fixtures under
`tests/fixtures/fractal/` and the current copied scripts. The input supplies
original sparse-test inputs, lane-definition paths, real web source files and
source witnesses for declared input directories. These tree-shaped fixtures
are not vendored into this repository. The committed fixtures contain only
policy, directly needed non-moving scripts/testdata, six original test
infrastructure helpers and the gate-evidence documentation section.
`tests/fixtures/fractal/PROVENANCE` records their source blobs and the input pin.
The fixture source's flake is never evaluated.

The workflow-generation self-test also uses the original pinned `effect-utils`
source and its real `genie` binary. The development shell supplies both input
paths as `MERGEMASTER_FRACTAL_FIXTURE` and `MERGEMASTER_EFFECT_UTILS`.
The external `effect-utils` source is linked as untracked sandbox environment,
matching Fractal's `ci-sparse-tree --link repos` behavior.

### Advancing the Fractal fixture pin

1. Change `inputs.fractal-fixture.url` in `flake.nix` to the reviewed full
   Fractal commit SHA, then run `nix flake update fractal-fixture`.
2. Compare every moving path against the new source commit's Git blob
   (`git ls-tree -r <source-sha> -- scripts`), update the as-is copies where
   needed, and regenerate `scripts/PROVENANCE`. Every source/destination blob
   pair must remain equal; do not patch a moving script to accommodate a test.
3. Review the small committed fixtures against the new source, update their
   `PROVENANCE` and `infrastructure-PROVENANCE` (including the documentation
   section's source range), and check that source-selected layout witnesses
   still cover the tests' original inputs.
4. Run the complete `nix develop -c bash scripts/test-scripts` suite and
   `nix flake check`, then require both hosted architecture jobs to pass.
   The list of moving self-tests present and run must remain equal.

The original `script-test-supervisor` and its Python dependencies own fixture
process cleanup on Linux; the original `git-env-clean` removes inherited
repository selectors, and `ci-parallel-tests` collects failures across the
suite. The runner also isolates home/config/state directories and disables
inherited Git configuration. It removes its temporary repository on exit.
`GENIE_FRESHNESS_JOBS` controls parallelism (default 6).
Failed-test logs are retained under
`${XDG_CACHE_HOME:-$HOME/.cache}/mergemaster-script-tests`, or the directory
specified by `CI_PARALLEL_TESTS_KEEP`. The suite needs no network service or
running daemon after the pinned dependencies and sources are available.

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