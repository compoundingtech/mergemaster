# Changelog

## Unreleased

- Freeze all six policy root/header, command/base-input and declared-path matrices with exact generator-input equality and preserved refusal/diagnostic assertions.
- Capture real Python/Rust divergence witnesses in hosted CI, preserving accepted-main review provenance and explicitly pending or review-requested cases without fabricating observations or approval.
- Freeze exhaustive JSON encoder streams using per-stream byte counts/SHA-256 and fixed-codepoint diagnostic blocks instead of committing multi-megabyte output.
- Record per-test native-only assertion/callee evidence for 111 shared-file inventory entries, without exempting Python-backed tests in the same files.
- Freeze complete legacy JSON output and policy check-name matrices, preserving their raw codepoint, duplicate-key, invalid-input and selected-value assertions.
- Freeze all six argparse oracle matrices as versioned driver/input/stdout/stderr/exit fixtures; compare Rust directly with frozen bytes while the existing corpus check independently replays the complete generators.
- Pin oracle tests to an explicit CPython 3.14.7 derivation and independent hash-pinned crate-key sources instead of committed runner fixtures; freeze initial CLI/signed-pack observations with exact replay checks. Keep the shared keys helper warning-free in path-included test targets without per-binary lint expectations.
- Make the copied-script oracle migration-aware with exact per-path removal tombstones, a complete removal-wave inventory and retained shared-fixture byte/mode pins. CI separately enforces append-only paths, immutable removal waves/tombstones against the trusted PR base or previous main commit, failing closed without history; retain all in-tree removal/drift checks and remove no Python sources. Supply Git to the sandboxed regression check and isolate temporary repository configuration and signing from the host.
- merge-pr: use the SHA-pinned async merge API for stacked PRs, refuse open downstack bases and unexpected outcomes, and verify the completed merge commit after bounded polling.
- merge-pr: verify the merge commit's parents and tree before its authorship; refuse the personal identity regardless of email case and in its GitHub noreply form.

## [0.11.0] - 2026-11-20

- Bind report-only queue batches with ordered repeatable `--member` heads, exact two-parent first-parent-chain validation back to BASE, precise `source_unbound` diagnostics, and additive v1 `queue_binding` metadata; preserve the no-member single-PR form.
- Add a fail-closed merge-time PR gate with durable independent exact-head verdicts, sensitive-path second review, hosted CI attempt/overlap checks, and local merge-tree verification.
- Accept explicit `GO compoundingtech/mergemaster#N` / `NO-GO compoundingtech/mergemaster#N` reviewer subjects with the head SHA in the content; keep the merge rule brief and put operational detail in `merge-pr --help`.
- Bind verdicts only to explicit GO/NO-GO subjects and full head SHAs; ignore casual content and abbreviated SHAs, and resolve named verdicts without consuming mailbox messages.
- Require the Mergemaster author-agent assertion, serialize merge-gate runs, recheck main before merging, and verify the resulting merge's parents/tree with an explicit revert warning on mismatch.
- Honor self-addressed author NO-GOs as withdrawals while excluding author GOs only from independent approval counts.
- Verify the CI-tested merge tree and compare overlap from its first-parent base.
- Refuse to merge when Johannes's personal identity is the author or committer of any PR commit or of the resulting merge commit.
- Keep Git evidence subprocess selectors correct in both auto-discovered and module-included integration-test targets.
- Compute PR-owned paths from the three-dot merge base and require a rerun reason for every workflow attempt greater than one at the exact head.
- Exclude the repository-owned `merge-pr` from the copied Fractal script oracle, with explicit provenance and regression coverage; copied scripts remain byte/mode guarded.
- Restore Cargo automatic integration-test discovery so every `crates/*/tests/*.rs` target runs.
- Run the ignored Linux O_PATH regression explicitly as non-root in CI using its exact full name and requiring one passing test, and cover absent configured or PATH-resolved evidence verifier binaries with end-to-end fail-closed gate tests.
- Route the local CI evidence gate's verification and projections through the trusted runner's pinned `mergemaster legacy-evidence-verify`, preserving BASE configuration and fail-toward-running behavior without a Python subprocess fallback.
- Mark the Linux search-only/O_PATH permission regression explicitly ignored by default; require a non-root account for an explicit run rather than returning a false pass under root.
- Provision the matching built binary in the development shell and propagate its absolute `MERGEMASTER_BIN` through the copied script-test harness, including per-crate gate fixtures in private clones.
- Inject gate self-test failures and record argv at the trusted binary boundary, retaining fail-closed assertions for timeout, invalid/empty output, crashes and unsupported interfaces.
- Make owned copies in the gate parity fixture owner-writable without changing executable bits, allowing repeated subtests against immutable Nix-store oracle sources.
- Add optional accepted-base gate `repository` policy: require an exact signed repository binding before evidence selection and comparison, with explicit unbound/mismatch rejection reasons; preserve existing behavior when omitted.
- Report the count of repository-binding refusals in gate comparison JSON without exposing rejected record contents.

## [0.10.0] - 2026-11-19

- Add the hidden `legacy-evidence-verify` entry before clap, composing complete project, require-all and ordinary verification with lossless argv, exact wire exits and real-binary pinned-oracle comparisons; unported ci_inputs helper requests fail closed.
- Skip the Linux search-only working-directory regression when the effective UID is root, which bypasses the permission restriction needed to exercise O_PATH.
- Add opt-in signed `OWNER/NAME` repository binding to `evidence wrap`, independently enforced signer repository allowlists, and exact expected-repository verification; retain historical unbound v1 evidence until consumers opt in.
- Bind v2 input hashing to the validated reachable graph and refuse observed link, entry-kind or directory-membership changes, including retargeted bridges and cached cycles; retain digest preimages and existing evidence verification.
- Bind physical v2 lookup directories to their Unix device/inode identities, refusing ancestor substitutions even through previously measured legacy trees; explicitly refuse v2 observation on non-Unix platforms.
- Bind the full requested v2 root lookup, including ancestor aliases and their link chains, and recheck its canonical resolution after hashing.
- Recheck the presence of all measured Nix closure members at the end of each workspace observation, including members not reached by workspace links; refuse members lost to GC without claiming to pin the store after observation.

## [0.9.0] - 2026-11-17

- Add shared Evidence App IaC and numeric-repository enrollment declarations, with central exact-main key storage rather than consumer App secrets. Registration, installation consent and deployment remain explicit operator actions. (#310)
- Add the central Rust evidence reconciler: scheduled and manual sweeps verify independently BASE-pinned evidence and recheck live PR/base/head identity before publishing checks with repository-scoped installation tokens. (#317)
- Preserve exact declared input-root link locations as explicit cross-root hop authority, separately from canonical measured endpoints; require standalone callers to supply the original declared root paths.
- Resolve v2 link targets component by component and require authority for every intermediate link; accept fully validated workspace dependency cycles while rejecting nonterminating link chains, and use logarithmic tracked-directory prefix lookups.
- Constrain nested links reachable through measured Nix closure directories to authorized closure members and measured input roots, including cross-member links, while retaining v1/v2 digest bytes and evidence verification.
- Share v2 link reachability validation across an entire workspace observation, expanding each canonical directory once per tracked-authority mode even across chained and shared inputs.
- Validate every reachable descendant of v2 workspace directory links, refusing nested escapes, reachable scratch paths and nonterminating link chains without changing digest preimages.
- Admit v2 workspace input links into independently remeasured closures of BASE environment Nix artifacts, binding every workspace observation to the original toolchain claims; keep arbitrary store paths, dangling links and scratch symlinks forbidden.
- Add opt-in `tree-sha256-v2` measured inputs: hash root symlink targets and resolved contents, and bind descendant link targets within declared measured trees or the verified-clean tracked checkout; retain legacy tree digests, scratch restrictions and evidence compatibility, with no blanket Nix-store exemption.
- Reuse borrowed check codepoints across member aggregation and stream uncovered summaries without temporary per-member formatted strings or joined buffers.
- Aggregate legacy member successes from original records: oldest metadata, weakest trust, maximum attempts, any input match, narrowed events and combined sampling key, with escaped sorted crate output.
- Share one check-owned record collector across legacy member verification, refusing aggregate record-budget exhaustion instead of resetting the budget for each retained member.
- Verify legacy members in sorted crate order with shared lazy-lane state, retaining original records and complete uncovered metadata while propagating uncaught exceptions globally.
- Hide retained legacy record and selection fields from callers; expose immutable original-record access and complete borrowed views instead of mutable trust metadata.
- Compute the legacy combined member key with streaming SHA-1 for oracle parity only, not for security.
- Retain original selected legacy records and typed selection metadata for member aggregation without a JSON conversion bridge.
- Add the library-only paths project dictionary with lossless comma splitting, shared literal-path validation and escaped JSON output.
- Preserve ordered legacy CLI preflight diagnostics before policy loading and other I/O.
- Decode Rust legacy skip policies from their original JSON text with lossless codepoint identities and wide positive-integer age limits; retain lazy age-overflow errors and remove the serde-value conversion bridge.
- Use the pinned Python interpreter for the noisy fsmonitor projection test so its hook executes inside Nix check sandboxes without `/usr/bin/env`.
- Derive the Nix package version from the Rust crate's Cargo manifest and check the packaged CLI's version against it, preventing release metadata drift.
- Accept borrowed lossless JSON/workflow selector names in the Rust legacy projection library, preserving parse-before-lookup refusals and existing scalar callers.
- Read selected legacy projection content with lossless filesystem paths and selector names, retaining lazy missing-path behavior and exact subprocess encoding refusals.
- Resolve lossless legacy configuration selector identities with strict returned-name decoding and unchanged preferred-layout ordering.
- Carry lossless declared paths through legacy projection, collection and prefix requests, preserving strict exclusions, selected index names and lazy whole-tree filesystem encoding.
- Preserve per-argument filesystem encoding and embedded-NUL refusal order in legacy projection, including repository arguments before projection, selected-content and configuration-selector paths.
- Compose per-crate legacy source-input keys from selected committed inputs, declared dependency paths and Git projection; preserve tree-first resolution and ordered unknown-crate refusals.
- Retain exact Python UnicodeDecodeError diagnostics for legacy JSON byte decoding, without changing callers that treat invalid encoding as an absent statement.
- Add lossless, uncapped JSON byte preflight with exact uncaught Python decode, JSON syntax and integer-limit exceptions for accepted-base source selection.
- Preserve complete Python errno exception subclasses and lossless filename diagnostics at legacy source filesystem boundaries, sharing projection's errno formatter.
- Map legacy source `ENOTCAPABLE` errors to Python's `PermissionError` on every platform defining it in pinned libc: FreeBSD, Apple platforms and WASI.
- Resolve accepted-base Rust test tools and inputs before historical bootstrap, refusing missing judged-base artifacts and malformed selected configuration without candidate fallback.
- Read the legacy verifier's standalone accepted-base no-tests allowance with exact missing, malformed and strict UTF-8 behavior, independently of the crate-inputs schema.
- Replace Linux Git final-wait sleep polling with pidfd readiness under the unchanged absolute deadline and direct-child cleanup contract; Linux >= 5.3 is required.
- Propagate the per-crate no-lazy-fetch setting through legacy projection reads, selectors and index writes without mutating the process environment.
- Compose verifier member keys with accepted-base inputs first, exact per-crate refusal provenance and no lazy fetching, accepting legacy treeish revisions.
- Pin Python Unicode digit and decimal classification for legacy test-count conversion, with generated-table freshness and exhaustive codepoint parity.
- Filter per-crate records by positive tests run when required, preserving Python Unicode decimal semantics, conversion exceptions and lazy crate/key mismatch behavior across both record indexes.
- Parse explicit legacy crate keys losslessly with exact first-separator, lowercase Git-id syntax and Python repr refusals; retain escaped-wire-only diagnostic delivery.
- Construct member and explicit-crate test-count bindings from the accepted base's standalone no-tests allowance, preserving lazy unjudged handling and member-key-first failure order.
- Prepare legacy member-project JSON with full lowercase tree-id validation before member-key reads, sorted crate keys, both input-index refspec namespaces and lossless escaped check names.
- Join legacy prefix collection and general configured/unconfigured judgment with retained projection keys, crate bindings, caller run inputs, preferred levels and reusable lazy-lane state; expose successful original-document views without a JSON conversion bridge.

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
