# Changelog

## [0.5.0] - 2026-11-06

### Changed

- Reduce gate latency with batched object reads via `git cat-file --batch`, one `ls-tree` per configuration load, and record lookup before content hashing. Reported debug-build medians: real dotfiles missing-key refusal 4.30 s → 0.74 s; seven-lane fixture queue hit 12.02 s → 1.41 s. (#63)
- Include `rustfmt` and `clippy` in the development shell. (#64)

### Fixed

- Pull-request live rechecks return computed `stale_head`, `stale_base`, or `pr_metadata_changed` refusals with event/live SHAs and metadata instead of a hard error: exit 0, no record. `decide()` applies the same refusal. (#65)

## [0.4.0]

### Added

- Native `evidence keygen` provisions signing accounts with script-compatible permissions, idempotence and refusal behavior. (#46)
- Canonical producer receipts verify job-scoped GitHub OIDC signatures and exact tree, recipe, attempt and artifact bindings. (#54)
- Trusted signer expectations derive from BASE policy, Git and authenticated API observations; unproven PR sources fail closed. (#58)
- Caller-bound `gate --event merge_group` supports explicit lane opt-in and report-only shadow decisions, never enforcement or skip. (#59)
- Caller-bound `gate --event queue` reports exact-tree evidence, verified-statement metadata and optional input comparisons without authorizing merges. (#61)

### Changed

- Admit a minimal ZIP reader dependency with stored, DEFLATE, BZIP2 and LZMA compatibility for native CI transport. (#47)
- Authenticated CI source archives extract in Rust with bounded sizes, fixed names and hostile-member refusals, without runtime Python. (#48)
- Shared signer tool-trust checks are factored and proved against the unchanged legacy Python oracle. (#52)
- Producer JWT verification uses AWS-LC instead of the RustCrypto RSA dependency family, retaining RS256-only acceptance. (#55)
- Native library validation covers legacy signer requests and Nix claims with Python-compatible numeric provenance; legacy CLI wiring remains unchanged. (#56)

### Fixed

- Legacy JSON number parsing stays local instead of enabling serde_json extensions across ordinary JSON entrypoints. (#57)
- Merge-group refusal regressions cover malformed bindings, optional fallback, reused hosted evidence and human-approval shortcuts. (#60)

### Documentation

- Document isolated exact-tree CI attestations, credential boundaries, queue semantics and rollout proofs; no signer deployment is implied. (#53)

## [0.3.0]

### Added

- Explicit `gate --event push` can reuse signed PR-head evidence for an identical
  default-branch tree after a squash or merge. The accepted BASE is the main
  commit's first parent; lanes must opt in to push events. Existing signature,
  lane, environment, workspace and freshness checks remain required.
- Push verification rechecks the live default branch and reports structured
  refusals: `tree_mismatch`, `event_not_allowed`, `not_default_branch`,
  `stale_push`, `no_parent` and `base_not_parent`.

### Changed

- Pull-request lanes allow merges from the accepted protected base when every
  non-first parent is an ancestor of BASE. Foreign side-branch merges refuse
  with `foreign_merge`, replacing the blanket `merge_history` refusal.
  Protection uses the BASE-to-HEAD tree diff, and lane measurements use the
  final HEAD tree, including merge-resolution changes.
- Merge-ancestry regression coverage includes parent ordering, criss-cross
  graphs, an accepted BASE that is itself a merge, and trusted octopus parents.

## [0.2.0]

### Added

- `nix:` artifact identities bind sorted store-path/NAR-hash closures, measured
  independently by the wrapper and signer. Executable lanes run a tool from the
  measured closure.
- Flake-check lanes bind the evaluated derivation, realized outputs and canonical
  executed command. Fresh evidence requires a local-only, substitution-disabled
  final rebuild under isolated, independently verified Nix settings; trusted
  daemon clients are required when using a daemon store.
- BASE lane policy can explicitly allow reused realizations without asserting
  fresh test execution. Failed realizations and rebuilds retain signed failure
  evidence without asserting outputs or freshness.
- BASE-declared materialized inputs and writable scratch roots support dependency
  trees such as `node_modules`. Input bytes are verified before and after
  execution; containment, symlinks, overlaps, tracked collisions and undeclared
  entries fail closed. Versioned workspace declarations retain v0.1 record
  verification compatibility.
- A read-only, informational pull-request reporter fetches the verifier from
  BASE and only candidate Git objects. It reports through the job summary and
  conclusion, accepts policy-approved reuse, and is not a required check.
- Scheduled script-parity drift checks retain upstream fixture compatibility.

### Fixed

- Missing BASE configuration now returns an explicit `config_missing` refusal
  instead of an opaque Git plumbing error.
- Copied evidence verification and queue-follow behavior track the upstream
  signed-evidence contract, including proposed-base gate decisions and dirty
  worktree refusal.

[0.2.0]: https://github.com/compoundingtech/mergemaster/compare/v0.1.0...v0.2.0
[0.3.0]: https://github.com/compoundingtech/mergemaster/compare/v0.2.0...v0.3.0
[0.4.0]: https://github.com/compoundingtech/mergemaster/compare/v0.1.0...v0.4.0
[0.5.0]: https://github.com/compoundingtech/mergemaster/compare/v0.4.0...v0.5.0
