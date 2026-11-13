# Changelog

## Unreleased

## [0.8.0] - 2026-11-13

- Resolve `ci-signed-tree`'s verifier adjacent to the script, not from the consumer working directory; keep consumer policy, Git operations and verifier arguments unchanged. Record the intentional oracle divergence with exact source/destination blobs. (see #141)
- Make direct execution an explicit `direct_exec: true` lane opt-in (default false, omitted when false), eligible only for exactly `["bun", "<tracked-relative-script>"]` with a `.ts`, `.tsx`, `.js`, `.mjs`, or `.cjs` script, no leading flag, absolute script path, `..` segment, or extra arguments. Execute only the canonical declared Nix runtime's `bin/bun`, never a dependency executable; default bare/relative commands retain PATH/checkout-relative wrapping. Opt-in and absolute Nix executable lanes require signed `executed_executable` (canonical absolute path) and `executed_artifact` (containing Nix artifact identity, runtime for opt-in) inputs, independently checked by the signer and required by the gate. Closure remeasurement is unchanged. (#159)
- Isolate the policy-path test fixture from host Git configuration and hooks.
- Rust legacy verification joins candidate collection with ordered miss precedence. (#155)
- Preserve exact zoned statement instants at microsecond precision for Rust legacy selection, including fractional offsets and negative epochs. (#157)
- Add lossless document value guards and borrowed selected-record facts, and share legacy routing and pre-lane input guards without losing Python code points. (#158, #162, #163, #164)
- Share selected-record lane and bound-file judgment with lossless document facts, preserving lazy provider reads and errors; callers still supply independently verified principal/lane/hash context. (#165)

## [0.7.0] - 2026-11-12

### Added

- Multi-system environments: `environment.json` carries a `systems` map from platform to toolchain, so x86_64 and aarch64 hosts each measure and sign with their own toolchain. The `system` input claim records the signing host; `toolchain_sha256` binds the whole map. Legacy single-system files still verify. (#151)
- Lane `argv[0]` resolves against the measured closure: absolute paths as before, or a PATH-resolved executable (signer worker falls back to the account trusted search path) that must canonicalize inside a measured Nix closure. Script-argv lanes keep execution binding. (#151)

### Changed

- Batch `tracked_clean` blob reads through one `git cat-file --batch` session, cutting `evidence wrap` overhead from ~9 s to a fraction of a second on factory-sized trees. (#147)
- Fetch the pinned Fractal fixture through shallow Git rather than GitHub's commit-tarball endpoint, preserving its source bytes and revision.

## [0.6.1] - 2026-11-10

### Added

- Rust legacy tree-record discovery preserves tree-tag-before-note ordering, exact record suffix identity and first-layout width filtering in SHA-1 and SHA-256 repositories. (#121, slice 3f-1)
- Rust legacy statement-shape validation covers decoded test records, zoned ISO calendar/week clocks, schema bool/float equality and integer-only exit codes. JSON byte decoding remains a separate port slice. (#122, slice 3f-2a)

### Changed

- Pin the immutable Python oracle to v0.6.0 and retire the first resync exception; retain the v0.5.0 oracle separately for the retired Python parity reporter's differential tests. (#120)
- Mirror six scripts and four policy/input fixtures verbatim from Fractal `787e8ed5`, including caller-side partial-clone hydration and signer refusal of missing objects. Guard the script resync with immutable revisions, exact blobs and executable modes until the next oracle repin. (#123, #124; exit tracking #115)

## [0.6.0] - 2026-11-10

### Added

- Native Rust parity-drift reporting preserves Python history boundaries and protected-ref behavior; the scheduled drift workflow now uses the Rust CLI. (#67, #71, #80)
- Rust legacy-policy parsing covers selected check headers, declared paths, commands, input ordering, signer-level overrides and normalized kind rules. (#88–#94)
- Rust legacy record judgment covers event routing, shards, ranked inputs, trust, age and ordered lane/input guards, with lazy lane lookup and microsecond-compatible timestamps. (#95–#100, #104, #105)
- Rust lane support includes selected schemas, exact definition digests and canonical entry text, Git entry discovery, hardened tree parsing and accepted-base/branch-point resolution. (#99, #101–#103, #106–#108)
- Rust input projection discovers Git inputs, selects workflow jobs and JSON entries, reads bounded selected content and projects the resulting Git tree. (#109–#114)

### Changed

- Pin an immutable Python oracle for Rust/keygen differential tests and guard remaining copied scripts against drift; formatter and warnings-denied Clippy checks are required by the Nix check suite. (#72, #73, #75, #76, #78, #79)
- Resync 29 scripts and their fixture witnesses verbatim from Fractal `e2721e52`, with a bounded oracle-check exception and a copied-suite runner that executes the checked working-tree scripts. Workflow adapter tests locate source blocks by strict anchors rather than old line numbers. (#116, #117)
- The Rust port remains incremental: copied Python entrypoints and the pinned v0.5.0 oracle remain in use; the post-release oracle convergence is tracked separately in #115.

### Fixed

- Inspect shallow legacy observations without weakening signature trust; align runner-kind matching, non-push newest-valid-pass selection and exact age boundaries with the oracle, and pin native gate status/GitHub-output contracts. (#82–#87)
- Cover degraded and unaccepted-level selection cases with distinct signer keys, and reduce equal-time record-ID ordering fixture flakiness. (#86, #91)

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
[0.6.0]: https://github.com/compoundingtech/mergemaster/compare/v0.5.0...v0.6.0
[0.6.1]: https://github.com/compoundingtech/mergemaster/compare/v0.6.0...v0.6.1
