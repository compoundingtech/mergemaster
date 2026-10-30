# mergemaster

Portable signed gate observations stored in immutable Git notes.

## Build and test

```sh
nix build
nix flake check
```

The flake provides the `mergemaster` binary and runs the Rust unit and Git
integration tests on `x86_64-linux` and `aarch64-linux`. Git, OpenSSH, Python 3,
and GNU coreutils are required by the integration tests.

For development:

```sh
nix develop
cargo test --workspace
cargo run -- evidence --help
```

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