# Changelog

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
