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
The default development shell provides both suites' real tool dependencies,
pinned source inputs and `MERGEMASTER_BIN` pointing to this flake's built binary.
Script tests propagate that absolute path to child gate fixtures, including
private clones. They run on the host, not inside a Nix derivation or a nested
bubblewrap sandbox.

Rust signer/verifier parity tests read the immutable v0.6.0 Python source pinned
by the `python-oracle` flake input, not the working-tree scripts.
`MERGEMASTER_PYTHON_ORACLE` names that source root and is required for those tests;
the dev shell and `checks.evidence` set it automatically. The production package
does not depend on the oracle or run its parity tests.

`checks.oracle-scripts` compares copied scripts' bytes and executable bits with
the pinned oracle in both directions: additions, deletions and edits fail.
Only repository-owned `PROVENANCE` and `test-scripts` are exempt. The retired
Python parity-drift tools are absent from both trees; the scheduled drift check
continues to use the Rust CLI.

For development:

```sh
nix develop
cargo test --workspace
cargo run -- evidence --help
```

## Producer receipt verification

`evidence::producer_proof::verify` authenticates a canonical v1 receipt using an
RS256 GitHub OIDC JWT whose exact string audience commits to the receipt SHA-256.
It checks expiry, repository/run/attempt/check-run identity, immutable reusable
workflow identity, and independently supplied BASE/tree/recipe/artifact bindings.
Receipts reject unknown/duplicate fields, noncanonical JSON and undeclared
action-key backends. Payload results remain producer assertions, not proof that
hostile candidate code tested honestly.

This library API does not fetch GitHub metadata, grant gate trust or access a
signing key. Its caller must obtain expectations from protected policy, Git and
authenticated attempt-specific APIs, and keys only from GitHub's fixed issuer
JWKS endpoint. Candidate artifacts cannot supply either. Focused refusal tests:
`nix develop -c cargo test -p mergemaster-evidence --lib producer_proof`.

JWT cryptography uses jsonwebtoken's supported AWS-LC backend; receipt verification
still permits **only RS256**, regardless of the backend's other algorithms.
This avoids the RustCrypto `rsa` dependency and its unused EC/Ed25519/HMAC crates.
AWS-LC requires a native C/C++ compiler; its default non-FIPS build does not
require CMake, Go or bindgen ([build requirements](https://docs.rs/aws-lc-rs/1.18.1/aws_lc_rs/#build)).
No custom cryptographic provider or additional accepted JWT algorithm is introduced.

## Provision a signing account

Run as the non-root account that will own the key, using a public alias rather
than a real host or account name. Provisioning is non-interactive:

```sh
mergemaster evidence keygen --name build-one --level host > enrollment.txt
# Special accounts may explicitly override the account home:
mergemaster evidence keygen --name signer-one --level agent --home /absolute/account/home
```

The command creates a private ed25519 key, bare scratch repository and signer
configuration under `~/.config/st`. It prints only the allowed-signers enrollment
line on stdout; diagnostics go to stderr. Submit that line to `.st/evidence-keys`
by pull request. Repeating the same invocation preserves the key and configuration;
conflicting configuration, unsafe ownership/modes and symlink targets are refused.
The native command requires Git and OpenSSH, not Python. The legacy keygen
entrypoints have been removed. Rust integration tests own every former keygen
self-test and native-parity assertion, running the same cases against the
independent pinned Python oracle (never a working-tree Python implementation).
They also check cross-implementation reuse without changing bytes, modes or
timestamps. Run `nix develop -c cargo test -p mergemaster-evidence --test keygen`
(non-root).

Frozen host/agent provisioning and reuse recordings use a public test-only key
in `tests/fixtures/oracle/keygen.json`; `tests/oracle_corpus.py` replays them
independently. Retained copied self-tests are discovered from this checkout so
removed leaves cannot silently return from the oracle fixture.

### Advisory pre-signing notice

`mergemaster evidence presign-notice` replaces the Python notice adapter and its
self-test. It reads `LINES`, `BASE_SHA`, `REPOSITORY`, `PR_NUMBER`, `GH_TOKEN`
and `GITHUB_STEP_SUMMARY`, retaining the decision record, annotation and appended
summary bytes. Unreadable evidence produces no unsupported notice; the command
always succeeds and never controls a gate. Git reads the accepted base's lane
definitions and `gh api` reads the pull request's changed paths.

Consumer adapters provision the accepted base's pinned, SHA-256-checked release
and verify its GitHub attestation before running the native command. Missing pins,
unavailable releases and older releases without this command retain the advisory
fallback. Provisioning explicitly errors on runners other than x86_64 instead of
silently substituting that fallback for an incompatible release asset.
Rust tests own the former self-test assertions; frozen independent Python
recordings are replayed by `tests/oracle_corpus.py`.

## Evidence gate SLO counters

```sh
mergemaster evidence slo --repository OWNER/NAME --hours 24 --json
```

This native, read-only command reports completed `Workspace CI` evidence-gate
decisions by check and event, including skipped/shadow satisfaction, producer
splits and produced-but-not-verified reasons (target zero). `--since` and `--until`
accept ISO timestamps; `--max-logs` bounds log downloads (default 300). It requires
authenticated `gh`, not Python, and never starts runs or writes to GitHub.

`scripts/ci-evidence-slo` and its self-test are removed. Every former self-test
assertion now lives in `crates/mergemaster-evidence/tests/slo.rs`. The focused check
is `nix develop -c cargo test -p mergemaster-evidence --test slo`. Frozen CLI
recordings in `tests/fixtures/oracle/slo.json` are compared byte-for-byte against
the immutable `MERGEMASTER_PYTHON_ORACLE` source with pinned CPython 3.14.7 and the
native command, both in that integration test and `tests/oracle_corpus.py`.

Timestamp parsing follows pinned Python `datetime.fromisoformat`, including
basic/week dates, reduced-precision clocks and naive intervals. Mixing naive
and timezone-aware bounds exits 1 with the Python `TypeError` message; intentionally,
Rust omits the Python crash traceback. Only that frozen case compares the message
substring instead of exact stderr. A nonzero `gh` log-download exit remains
tolerated, but deadline, spawn and read errors fail the command rather than
silently counting an unknown producer.

## Copied evidence scripts

The evidence scripts and their self-tests originate from
`compoundingtech/fractal` commit
`e83871ec919f95b3b3e2a9a1cd211c2ac37babda`, with individually recorded upstream
ports in `scripts/PROVENANCE`. Their original Fractal configuration paths, command
names and defaults are intentionally unchanged; this extraction does not make
the scripts general-purpose replacements for the Rust CLI. The runner recognizes
kernel-verified gate-slot memory caps without moving the check out of its
admitted scope; build and seat-lane caps still require memory and CPU limits.
The accompanying systemd service and timer files are shipped as source only:
the flake does not install, enable or run them.

The pool runner preserves Fractal's two-hour queue aging and free-tree waiter
liveness rules. Kept cargo targets are tagged on creation and emptied above
the 80 GB cap only when tagged or owned by the pool; untagged caller-owned
targets remain untouched, and the cache tag alone never counts as a warm build.
Waiting runs refresh the base's runner every ten minutes and hand over to a
changed copy in the same process, preserving their ticket and start time.
Tickets name their queue-rule version; waiters defer only to their own rules
or newer, and never hand over after acquiring a tree.

Readiness treats a cancelled run as no evidence unless a job it judged failed.
Cancelled attempts do not count toward satisfied lines or hide real failures,
and are reported separately as `cancelled_runs`. Timeouts still count as failures.

The legacy verifier selects the newest pass that validates. It passes over only
passes from a level accepted by no kind of the check, or carrying another tree's
lane definition; every other validation rule still applies. A later failure
(within the clock-skew margin) refuses regardless of its level or lane definition.
With no valid pass, the newest record decides as before. Results include
`decided_by` and `skipped_newer` so the decision can be audited.

Run the script suite independently:

```sh
nix develop -c bash scripts/test-scripts
# Or, with dependencies, all three pinned-source variables and MERGEMASTER_BIN set:
bash scripts/test-scripts
```

`scripts/test-scripts` discovers every copied `scripts/*-test` self-test from
`MERGEMASTER_PYTHON_ORACLE`, including `evidence-verify-test`; `st-test` and
`fractal-test` are production entrypoints, not self-tests. Fixture-only tests are
not added to the suite. The oracle variable is required; there is no working-tree
script fallback.
The runner creates a temporary Git repository using the immutable non-flake
`fractal-fixture` input, then overlays the small intentional fixtures under
`tests/fixtures/fractal/` and the immutable oracle scripts. The input supplies
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

### Upstream parity reporting

`mergemaster parity-drift --fractal-repo PATH --ref origin/main --report-only`
lists commits touching mapped origin paths after the last `# Port:`
SHA in `scripts/PROVENANCE` (or the extraction SHA before any ports). Watched
paths include every fixture origin manifest, including infrastructure helpers.
Full-history traversal retains merged branch changes even when a merge discards
them, and includes merge-only resolutions relative to each merge's first parent.
Each entry in the JSON `commits` array is one full SHA and subject, not patch text.
The scheduled **Fractal parity drift** workflow reports every six hours without
blocking CI or changing evidence policy. It reads history only, never upstream
scripts. Omit `--report-only` to return exit 1 when newer commits exist; invalid
history or a missing watermark is an error in either mode.
The workflow builds the Rust binary from the checkout's locked Nix flake before
fetching upstream history, retaining read-only permissions and advisory reporting.
The Rust differential integration test compares the unchanged Python implementation
and assertions from `MERGEMASTER_PYTHON_PARITY_ORACLE` against real local Git histories.
This separate `python-oracle-parity` input retains v0.5.0's retired reporter and suite;
the dev shell and `checks.evidence` set it without adding a runtime dependency.
The command defaults to `scripts/PROVENANCE` at the caller's Git top level; outside
a checkout, pass `--provenance`.

This is a newer-commit alarm, not proof of complete parity: older unported
commits remain in the cutover inventory. Record each port's upstream SHA,
scope, applied-hunk SHA256 and any conflict resolutions in `scripts/PROVENANCE`.
The destination blob column reflects the resulting copies; the original source
blob column remains the extraction receipt.

### Advancing the Fractal fixture pin

1. Change `inputs.fractal-fixture.url` in `flake.nix` to the reviewed full
   Fractal commit SHA, then run `nix flake update fractal-fixture`.
2. Compare every moving path against the new source commit's Git blob
   (`git ls-tree -r <source-sha> -- scripts`), update the as-is copies where
   needed, and regenerate `scripts/PROVENANCE`. Differences must be accounted
   for by recorded upstream ports and explicit conflict resolutions; do not
   patch a moving script merely to accommodate a test.
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

## Workflow adapters

`genie/evidence.ts` exports typed job fragments for evidence gates, pre-sign
notices, source retention, aggregate and per-crate signing, observation, and
the signed-tree shadow check. Consumers compose these objects into their
existing `githubWorkflow` configuration; there is no remotely executed
reusable workflow or composite action. Required checks, lane dependencies,
runner labels, environments, checkout steps, and action references are
consumer settings. Supply full commit SHAs for action references, with the
release tag in a source comment.

```ts
import { evidenceGateJobs, evidenceSourceJob } from './repos/mergemaster/genie/evidence.ts'

const actions = {
  checkout: 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1', // v7.0.1
  uploadArtifact: 'actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9', // v7.0.2
  downloadArtifact: 'actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333', // v8.0.2
}
const jobs = {
  ...evidenceGateJobs({ checks: ['linux-gate'], actions }),
  'evidence-source': evidenceSourceJob(actions),
}
```

Source retention fetches the accepted BASE and provisions its
`.mergemaster/tool-pin.json` release, verifies the binary digest and GitHub
release attestation, then runs `"$MERGEMASTER" evidence source`. It never embeds
or executes a Python producer, builds a candidate tool, or silently falls back.
For pull requests, BASE follows the gate's checked-out merge first parent when
its second parent matches the event's PR head; otherwise it uses the event base.
Merge groups use `merge_group.base_sha`; main-branch manual dispatches use
`github.sha`. Unsupported events fail without provisioning. The producer reads
this exported `BASE_SHA` and hashes its running executable through `/proc/self/exe`.
The informational job retains its existing names, `continue-on-error`, and
`ci-evidence-source-${{ github.run_attempt }}` upload containing exactly
`source.pack` and `receipt.json` under `${{ runner.temp }}/ci-evidence-source/`.

The event file follows the pinned Python `json.loads(bytes)` boundary, including
UTF-8 BOM and UTF-16/32 detection, non-finite numbers, and lone-surrogate escapes.
Unused event text is not copied into receipts; event-derived identities contain
only validated ASCII queue digits or arbitrary-precision positive PR integers.

The source receipt is version 2. Its `tool` identity is
`{repository, revision, release_version, binary_sha256}`, matching BASE's pin;
the executable hash must equal the pinned release digest. The pin is version 1,
for `compoundingtech/mergemaster`, with a lowercase 40-hex revision, `vN.N.N`
release version and lowercase 64-hex release SHA-256; additional pin fields are
tolerated. Operator-owned CI binding configuration uses `tool_pin_sha256`, the
SHA-256 of the **raw pin bytes**, instead of `recipe_sha256`. Whitespace changes
therefore change the binding. Version-1 source receipts are unsupported, not
converted or accepted through a legacy arm. Source retention is provenance,
not proof that checks passed or authorization for full trust.

`binary_sha256` is measured from `/proc/self/exe` inside the accepted workflow.
It is only as trustworthy as that workflow and its runner: matching tool
identity is not proof that the tool executed.

#### Source-receipt operator rollout and rotation

Roll out these four values together: the new `.mergemaster/tool-pin.json`,
the operator's raw-byte `tool_pin_sha256`, the operator's `accepted_base`,
and the fleet workflow's operator `workflow_sha256`. Nothing updates these
values together automatically. Every mismatch fails closed: full eligibility
is lost (and receipt validation can fail before eligibility is considered).
Publishing a new release does not revoke the old pin; only changing the
operator configuration revokes its acceptance.

Signing fragments take the consumer's full-history checkout steps, signing
environment, check names, and lane-specific web-note environment. `configDir`
and `legacyConfigDir` default to `.fractal` and `.st`; the accepted base decides
which key file exists. Signing script command names and record formats remain
unchanged.

The gate fetches its executable from the accepted BASE revision, including
the original pull-request merge-parent selection. Signers archive BASE's
scripts and read BASE's keys, never PR-head tools. Consumers must make the
scripts available at these unchanged base paths before using the adapters.
The observer job must remain in a default-branch `workflow_run`/manual
workflow, with its protected runner labels and default-branch checkout.
The signed-tree job must remain under `pull_request_target`, whose checkout
is the base branch; never override it to the PR head. Event selection,
protected environment enrollment, runner-group restrictions and check skip
wiring remain consumer policy, not adapter side effects.

Fractal consumers share their existing flake authorities:

```nix
inputs.mergemaster.inputs.effect-utils.follows = "effect-utils";
inputs.mergemaster.inputs.nixpkgs.follows = "nixpkgs";
```

Run `nix develop -c python3 tests/test-workflow-adapters.py` for the strict
TypeScript check and golden test. It renders both the unmodified pinned
`fractal-fixture` generators and the public fragments with Fractal's original
settings through the same real pinned effect-utils generator. The native notice
and source cutovers have explicit migration assertions; all other output must
remain byte-identical. It also compares every fleet evidence job and the
complete observer and signed-tree workflows against the committed fixture
YAML, allowing only those asserted cutovers. Provisioning cases cover malformed
pins, transport/attestation/digest failures, executable dispatch and accepted-base
selection; source failures remain failures, while notices retain their fallback.
The shell supplies `oxfmt`, which genie invokes after serialization;
without it genie silently emits unformatted YAML. The test retains the
consumer's queue/cache/sandbox wrappers. Original fixture action tags are
used only to prove unchanged output; this repository's hosted workflow uses
SHA-pinned actions.

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

Explicit `show --record` and `verify --record` inspection can read an existing
observation fetched shallowly without its subject commit. The raw observation
must still name exactly that subject as its sole parent, and any locally present
subject must match the signed tree. Object reads never lazily fetch missing
objects. This inspection-only allowance does not apply to `put`, producers,
gate/push decisions, policy verification, or wrapper reuse: those require the
subject commit to be present and its tree to match.
Both inspection commands include `subject_binding`: `"verified"` when the subject
was present and tree-checked, or `"subject-absent"` when only its signed claim
could be inspected. Both cases exit 0 on success; callers must check this field
when they require a locally verified subject binding.

The Rust evidence sources originate from `compoundingtech/fractal` commit
`d6e91e3b6db855c30b4d35f2e78a29a3948b1ded`. The evidence library is available as
`mergemaster_evidence::evidence`.

## Generic verifier consumer contract

`mergemaster gate` is a separate, BASE-pinned single-lane verifier. It does not
replace the copied Fractal scripts or make their daemon policy generic. The
consumer provides full 40-hex commit IDs for the accepted base and candidate
head, and authenticated Actions event data, never a PR-authored event file:

```sh
mergemaster gate --check graph-full-check --base "$BASE" --head "$HEAD" \
  --event-file "$GITHUB_EVENT_PATH" --format json
```

Commit `.mergemaster/tool-pin.json`, `evidence-keys`, `lanes.json`, and
`environment.json`, plus the trusted base workflow. There is no `.st` or
`.fractal` fallback. Every policy, allowed signer and environment declaration
comes from BASE Git objects; HEAD supplies candidate objects and observations.
The explicit pin schema is:

```json
{"version":1,"repository":"compoundingtech/mergemaster","revision":"<full immutable generic-verifier commit SHA>"}
```

The revision notation above is not a runnable pin. The bootstrap must validate
the allowlisted upstream and immutable revision and authenticate the release
artifact's digest/provenance before invoking its absolute executable. A SHA
alone is not binary provenance. Missing artifacts must fail closed.
Release downloads additionally require a `release` object in this BASE pin:
`{"version":"vX.Y.Z","sha256":"<64 lowercase hex digits for the x86_64 musl asset>"}`.
`revision` still identifies the exact source commit. Both values must be real
published identifiers, not the illustrative notation here.
`evidence-keys` uses OpenSSH allowed-signers lines, for example:

```text
agent/larch ssh-ed25519 <provisioned-public-key>
agent/sorrel ssh-ed25519 <provisioned-public-key>
```

Provision actual public keys; the example deliberately makes no key-to-machine
association. Version one accepts Ed25519 public keys with literal `agent/name`
or `host/name` principals (comma-separated lists allowed). Names contain ASCII
letters, digits, `-`, `_`, or `.`. The only supported optional key restriction is
`namespaces="git"` before `ssh-ed25519`; trailing comments, blank lines and
comment-only lines are allowed. Unsupported key types/options, principal
patterns, invalid SSH wire keys and signer files with no keys fail closed.

To bind gate evidence to its consumer repository, set the optional top-level
`"repository": "OWNER/NAME"` in the accepted BASE `.mergemaster/lanes.json`.
The gate requires an exactly matching signed `Statement.repository`, including
case, before any record enters selection or `--compare-head` reporting. Missing
bindings reject the record with `repository_unbound`; differing bindings reject
it with `repository_mismatch`. A rejected record cannot shadow valid evidence.
When comparison runs, its JSON decision includes `repository_refused`: the number
of signature-verified comparison records rejected for an absent or mismatched
repository binding (zero when none). This count exposes replay attempts without
including rejected record contents. Decisions without comparison omit the field.
The identity uses the same literal `OWNER/NAME` validation as `evidence wrap
--repository`; URLs, extra path components and whitespace are invalid.

This policy is opt-in: omitting `repository` preserves historical behavior,
including unbound records. Shared signing keys alone do not isolate repositories;
enable the policy before relying on that isolation and produce evidence with
`evidence wrap --repository OWNER/NAME`. The accepted-base policy is the sole
binding authority; the gate does not infer it from HEAD, remotes or the ambient
`GITHUB_REPOSITORY` environment variable.

A Graph-shaped `lanes.json` is:

```json
{
  "version": 1,
  "pull_request": {
    "same_repository": true,
    "authors": {"mode": "none"},
    "base_relation": "ancestor"
  },
  "protected_paths": [".mergemaster/", ".github/workflows/", ".github/actions/"],
  "bootstrap_paths": ["genie"],
  "lanes": {
    "graph-full-check": {
      "argv": ["tools/graph", "check", "--full"],
      "definition_paths": ["tools", "lib", "package.json", "tsconfig.json", "vitest.config.ts"],
      "trust_levels": ["agent"],
      "mode": "required_evidence",
      "events": ["pull_request"],
      "environment": {
        "manifest": ".mergemaster/environment.json",
        "paths": ["package.json", "tools", "lib"]
      },
      "protected_edits": "reject",
      "remediation_argv": ["mergemaster", "evidence", "wrap", "--check", "graph-full-check"]
    }
  }
}
```

Use the actual committed consumer paths; omit `bootstrap_paths` when there is
no generator/bootstrap source. Declared bootstrap paths are automatically
protected, as are `.mergemaster/`, `.github/workflows/` and `.github/actions/`;
policy can add protection, not remove it. Prefixes match complete path
components, not globs. Missing input paths, escaping paths, symlinks,
submodules, unknown schema fields and unsupported versions/policy fail closed.
The only alternate lane mode is `optional_fallback`; optional positive
`max_age_seconds` bounds signed observation age, including fractional seconds
(age equal to the limit is allowed). Observations more than 120 seconds in the
future are refused. `authors.mode=none` adds no
author restriction but does not bypass repository or signer checks. An explicit
allowlist uses `{"mode":"allowlist","logins":[...],"git_authors":[...],
"git_committers":[...]}`: all lists must be nonempty, Git identities are exact
`Name <email>` strings, and opener, actor, triggering actor and branch commit
identities must all be eligible.

The strict environment schema describes a complete immutable external runtime
and dependency closure; no Nix file is required:

```json
{
  "version": 1,
  "systems": {
    "x86_64-linux": {
      "runtime": {"name": "bun", "identity": "sha256:<64-hex-runtime-artifact-digest>"},
      "dependencies": {
        "external-library": {"name": "external-library", "identity": "git:<40-hex-commit>"}
      }
    }
  }
}
```

Replace notation with measured identities; mutable version labels and external
checkout paths are not identities. Supported systems are `x86_64-linux`,
`aarch64-linux`, `x86_64-darwin`, and `aarch64-darwin`. Every artifact has exactly
`name` and `identity`; identities are `sha256:` plus 64 hex digits or `git:` plus
40 hex digits. List every non-repository dependency under sorted named
`dependencies`; use an empty map only for a genuinely empty external closure.
The wrapper must measure and enforce this closure before claiming provenance.
The verifier reads data and Git blobs only, never executes the declared runtime.

Signer and verifier share `gate::config::expected_inputs`. Hashes are lowercase
SHA-256 of compact JSON tuples. Environment binding is
`[1, BASE_environment_bytes_as_integer_array, declared_paths, files]`;
toolchain binding is `[1, resolved_toolchain]`; lane-definition binding is
`[1, check_name, lane, definition_files]`. Expanded files are sorted by UTF-8
path bytes and encoded as `[path, Git_mode, content_sha256]`. Toolchain struct
fields are ordered `runtime`, `dependencies`; artifacts are `name`, `identity`.
Lane struct fields follow the example, then `max_age_seconds` if present.
The environment declaration is ordered `manifest`, `paths`. Dependency map
keys are byte-sorted. Environment bytes are preserved exactly, including
whitespace. Pull-request mode requires exact signed commit and tree identity.
Explicit push mode below permits commit transfer only for identical trees.

`skip/satisfied` means trusted evidence covers the exact lane, not a skipped
required GitHub job. `refuse` must fail the required check; `run` must execute
the real fallback or fail. A computed decision exits zero even for refusal;
usage/internal failures exit nonzero and missing outputs are never success.
Use a read-only, base-owned `pull_request_target` bootstrap with no candidate
checkout execution or private signing keys. Publish the required check on the
explicit HEAD, recheck unchanged HEAD and accepted base before success, and
require strict up-to-date branch protection. Graph's required-evidence lane
does not execute its full check in the publisher job. The separate unprivileged
validate job may execute candidate code. Copied Fractal wrappers retain their
original contracts and are not generic environment producers.

The final authenticated pull-request recheck refuses with `stale_head` when the
live head SHA moved, `stale_base` when the live base branch tip moved, or
`pr_metadata_changed` when the head/base repository or base ref changed.
These decisions exit zero with `outcome=rejected` and no record; `summary`
names the changed side or metadata field and includes event/live values and SHAs.
Authentication and API failures remain nonzero errors, not refusal decisions.

A decision authorizes only the `base`, `head` and `tree` IDs that it names. The
local recheck compares endpoint values and does not fence concurrent local ref
writers: a ref can move after the final recheck and before output is written,
and a move that is later restored (A to B to A) is not detected. Consumers must
bind their action to the named IDs, for example with a compare-and-swap on the
target ref, and must not treat `skip=true` as authorization for whatever
checkout or ref is current.

The JSON result contains `version`, `check`, `base`, `head`, `tree`, `decision`,
`outcome`, `reason`, `record` (an immutable record ID or null),
`protected_paths` (the touched protected paths, empty otherwise), and `summary`.
`protected_edits: "reject"` always refuses protected edits, even for
optional-fallback lanes. A BASE-authorized `human_approval` policy permits the
explicit review/hosted-check path described below; agent signatures alone
never authorize protected changes.
The stable reason codes are `satisfied`, `base_not_ancestor`, `foreign_merge`, `protected_paths`,
`ineligible_event`, `no_record`, `invalid_record`, `untrusted_signer`,
`wrong_check`, `stale_tree`, `degraded`, `untrusted_tier`, `wrong_commit`,
`untrusted_level`, `future_dated`, `too_old`, `check_failed`, `wrong_command`,
`wrong_input`, `wrong_definition`, `workspace_dirty`, `approval_evidence_missing`, `human_approval_missing`,
`hosted_check_missing`, `human_approval_satisfied`, `stale_base`, `stale_head`,
and `pr_metadata_changed`. Consumers branch on these codes, not
diagnostic prose. Malformed configuration or unavailable Git plumbing is an
error, not a computed satisfaction result.
In pull-request mode, every merge in `BASE..HEAD` is allowed only when **all
non-first parents are ancestors of accepted BASE**. This permits carries of the
protected base branch, including older base tips, but not side-branch merges.
Any other merge returns `foreign_merge`, including optional-fallback lanes;
this reason takes precedence over protected edits, while `protected_paths`
still lists every touched protected path. Policy protection uses the complete
BASE→HEAD tree diff, and lane/environment bindings use the final HEAD tree:
conflict-resolution edits cannot disappear inside a per-commit walk. Protected comparisons
use Unicode NFKC normalization and lowercase component matching, including ancestor
replacement paths; signatures cannot authorize replacing a protected root with
a symlink. Authenticated live head/base movement yields a refusal as described
above; unavailable live authority remains an error with no decision output.

`--github-output FILE` appends `skip`, `record`, `outcome`, `refuse`, and
`refusal` only after computation completes. `refusal` is the reason code for
a refusal, otherwise empty. Local decisions require the checkout's live `HEAD`
to equal the requested head and a local branch or remote-tracking ref at BASE.
The gate snapshots mutable branch refs and refuses if they change before output.
This does not authenticate a GitHub event. With an event, the trusted
`GITHUB_REPOSITORY` context and event repository/base/head must agree.
`GITHUB_TOKEN` and an installed trusted `gh` executable are required to re-query
the live PR head and base branch immediately before emitting a decision.
Author allowlists additionally require opener, actor, triggering actor and every
branch commit's exact author/committer identities.

The native gate emits one compact JSON line and exits 0 for a computed decision,
including `refuse`; consumers must inspect `decision`, not just the exit code.
Errors emit no decision JSON or GitHub outputs and return nonzero. GitHub outputs
use lowercase booleans and an empty `record` for JSON null. This native protocol
is not the legacy `evidence-verify` document consumed by Fractal's
`ci-evidence-gate` (`satisfied`, `tier`, policy/trust/matching fields).

The library's `evidence::legacy_policy` schema helpers are separate from native
lane authorization. Command/input helpers preserve raw commands and bindings;
base-input helpers validate declarations without reading files. They do not
evaluate evidence or substitute for kind-rule validation.
Input-value helpers preserve policy/ranking order and shard declarations,
including the distinction between absent and explicit-null shard counts.
Level overrides validate accepted signers, required events and lane-binding modes,
then normalize command placeholders and the required-input/binding-key union.
`PolicyDocument::into_rules` completes kind/level validation and normalization
before returning typed policy rules; raw kind entries are not exposed to callers.
`legacy_verify::value_checks` judges ranked/base inputs and complete shard results
without granting signature trust or changing native gate behavior.
`legacy_verify::base_input_values` reads accepted-base bindings in kind/input order,
using inherited `no_lazy` Git show transport. Names remain lossless, later writes
replace values without moving their first position, and nonzero reads mean `absent`.
Raw blob capture retains the approved 1MiB fail-closed resource divergence.
`legacy_verify::argparse_options` exposes the pinned verifier's complete ordered
option metadata: aliases, destinations, actions, defaults, metavars, nargs,
requiredness and exclusive groups, consumed by the hidden legacy entry.
`argparse_int` preserves unbounded decimal conversion and Python's 4300-digit
limit. Conversion errors retain the exact unbounded argparse argument-repr
diagnostic, including whitespace, controls, quotes and lone surrogates.
`argparse_usage` renders the pinned usage layout at an explicit formatter width,
retaining lossless program text and interpolation provenance for future safe sinks.
`argparse_help` adds the complete uncolored help text, preserving Python textwrap
hyphen breaks and help indentation across explicit formatter widths.
`argparse_parse` consumes lossless argv with unbounded integers, defaults, appends
and exclusive groups; diagnostic rendering remains a separate library surface.
`argparse_diagnostic` renders exact uncolored parser stdout/stderr and exit status.
Manually constructed invalid option indices return typed `InvalidOption`, never panic.
Approved ANSI-styling divergence: Rust help, usage and errors are always uncolored,
independent of TTY, FORCE_COLOR, NO_COLOR and TERM. Python 3.14 `_colorize.can_colorize`
may add ANSI SGR styling; stripping only those sequences yields identical bytes.
Non-TTY and NO_COLOR output, streams and exit codes remain exact. No CLI is wired.
`cli_adapter` decodes raw POSIX argv with surrogateescape, returns successful
namespaces without reparsing, and routes parser exits through the safe sink.
It resolves formatter width from positive Python-integer COLUMNS, original stdout
terminal columns, then 80. Its fixed program name is `evidence-verify`: an approved
divergence only when Python's argv[0] basename differs.
`ParsedArguments::preflight` applies main's ordered validation directly to that
namespace before any I/O. Kinds and level-list validation retain lossless strings;
presence, truthiness, repeated stores/appends and unbounded integer positivity
are not narrowed through serde or a second parser.
`cli_dispatch::resolve_tree` adds the original main's tree-resolution boundary;
its error writer preserves single-check versus require-all envelopes and exits.
Revision capture uses the shared collector with the existing 1MiB RawBlob
metadata divergence, original expression identity and owned 60-second deadline.
`mergemaster legacy-evidence-verify` intercepts raw argv before clap and composes
these complete paths, preserving stdout/stderr, exit status and final JSON LF.
It never calls `AcceptedSource` or `json_bytes::parse`; their outstanding #280
resource/security prerequisites remain open but unreachable, not silently satisfied.
The unported `ci_inputs_unchanged`/`unresolved_ci_inputs` helpers have no callable
CLI route; helper-name options and positional requests fail closed as unknown arguments.

The local `scripts/ci-evidence-gate` invokes this binary entry for ordinary
verification and both input/member projections. Its trusted workflow/runner must
provision a pinned `mergemaster` on PATH or set `MERGEMASTER_BIN` to its absolute
path, outside the candidate checkout. Missing binaries fail toward running;
there is no Python fallback. BASE still supplies policy, keys, lanes and the
legacy capability markers/helper-presence guards. The decision line's
`verifier_sha256` remains the BASE Python capability-source digest, not a binary
attestation; the runner owns the binary pin.

Python is not yet removable: the gate's `ci_inputs_kept` still imports the BASE
verifier for the unported `ci_inputs_unchanged` helper. Other copied consumers and
the pinned differential oracle also still use Python. This local gate patch is
not a claim that Fractal's deployed workflow has switched binaries.

The Linux O_PATH permission regression is explicitly ignored in the default
libtest suite because root cannot exercise it. As a non-root account, run
`cargo test --workspace linux_git_search_only_cwd_uses_o_path -- --ignored`;
an explicit root run fails instead of falsely passing.

`cli_dispatch::project` composes complete member, policy-backed and plain project
early returns before key/lane/run/log preparation. Policy default paths and
base-input names stay borrowed through output; explicit paths replace defaults.
The member branch deliberately precedes policy loading, matching original main.
`cli_dispatch::required` prepares signers, then explicit lanes, then policy,
and selects `require_all_cli` before ordinary run/log/crate preparation.
`with_signers` captures the operation result and explicitly closes its owner;
close errors override that result, as in original main's finally clause.
`cli_options` retains ordinary caller restrictions as lossless codepoints after
preflight: command JSON, ordered comma lists, bindings and unbounded age values.
Conversion does no filesystem I/O; overflowing ages retain the existing deferred
timedelta-overflow judgment rather than narrowing argparse's accepted integers.
`cli_verified::Outcome` writes complete single/member success and refusal
dictionaries, including selection, missing-member and shadow-log overlays.
Log requests may defer the system-clock sample until the readable signed head's
freshness phase; explicit fixed-clock reader APIs retain their existing behavior.
`cli_ordinary::verify` composes policy, lanes, run/base inputs, log keys, crate
bindings, eager/lazy lanes and complete single/member verification in main order.
It explicitly selects CLI transports and retains base-hash/log owners through
the output callback, within signer finally ownership.
Approved security divergence: option-shaped `--policy-from` is refused before I/O
in every CLI mode; the oracle passes it to Git as an option. Native APIs are unchanged.
Approved terminal/log output divergence (#245): `terminal_sink::value` applies
unbounded Python-repr-style escaping to C0, DEL, C1, lone surrogates and every
backslash, without repr quotes. `RenderedHelp::write_terminal` escapes only
code-point interpolation ranges, preserving structural usage/help/error terminator
newlines. Exact lossless library text is unchanged; whole-message escaping is
never used. Caller-constructed invalid ranges/codepoints or unsafe literal controls
return typed sink errors, not panics; callers must discard partial output on error.
No CLI is wired; these are explicit terminal/log writer surfaces for that boundary.
`value_checks_document` applies that same guard body to a validated input object,
preserving Python code points (including lone surrogates) in keys and values.
Private borrowed views avoid converting statements into native String maps.
`InputMap` carries borrowed run-input lookup through judgments and value guards;
native `BTreeMap<String, String>` and lossless `ValidatedInputs` share that path.
The native `value_checks_document` convenience signature retains map inference.
`run_inputs::RunInputs` borrows first-equals CLI pairs and accepted-base hashes,
retaining first key position with last value wins. Accepted-base values overwrite
caller claims; callers keep the reader's owned hashes alive for this InputMap view.
Full unbounded Python repr refusals remain library text, not a raw terminal sink.
Event helpers retain signer-level event order when narrowing check permissions
and identify shard parts only from the configured producer kind and index input.
Routing requires a signature-verified principal and a validated generic check.
The runner-prefix guard follows any required lazy lane lookup, before age/input
judgments; routing alone never authorizes a record.
The legacy clock/input guard takes an explicit clock and preserves future, age,
required-input, exit-code, command and value-check refusal order.
`legacy_verify::lanes::LaneRules` validates one selected accepted-base lane,
preserving optional-field truthiness without reading Git or authorizing evidence.
`cli_lane_git::definition_entries` separately uses inherited oracle Git and the
approved 64MiB TreeListing capture, retaining original revision codepoints in
resource refusals; native lane transport and OID validation remain unchanged.
`cli_lane_definition` streams lossless argv into definition digests, preserving
accepted-base existence/absence checks before candidate reads and exact missing
path diagnostics. Invalid caller-constructed argv codepoints have a library-only
invariant guard; parsed CLI rules cannot reach it.
CLI branch-point entry comparison uses bounded flat Documents and iterative
canonical equivalence, without building JSON strings: object order and integer
-0 normalize, but bool/int/float and signed float zero remain distinct. It
retains surrogate names/values and nonfinite metadata; native narrowing stays.
CLI `cli_lane_for::lane_for` composes those surfaces in oracle order: inherited
config/rev-parse/definition reads, no_lazy only for merge-base and branch-point
show. Scalar capture is RawBlob1MiB; branch-point lane text is LaneJson1MiB.
Original revision/check codepoints survive through the hidden CLI dispatch.
The CLI-only `cli_lanes::LaneRules` uses the flat lossless Document instead:
lane names and argv retain lone surrogates, and optional noniterable falsey
values raise the oracle TypeError after CI-input validation. Native APIs stay
unchanged. CLI lane JSON shares the approved 1MiB/256-depth/262144-node budget,
with typed lane-specific resource refusals; no dispatch is wired.
Pinned boundary cases cover exact-limit/+1 UTF-8 source bytes, mixed/empty
container depth and node charging (including overwritten duplicates).
Oracle comparisons explicitly raise its recursion limit, not assert stack depth.
Legacy definition hashing streams Python-compatible Git-entry/argv bytes,
including surrogateescaped filenames; native lane hashing remains unchanged.
Legacy lane-entry parsing preserves integer lexemes and reports unsupported JSON explicitly.
Canonical lane-entry comparisons use Python-compatible sorted compact JSON text,
not parsed-value equality; callers compare before validating the lane schema.
The two outer lane-name maps accept borrowed Python code-point names, including
lone surrogates; entry values still use the same lexeme-preserving scanner.
Existing depth/integer/float/extension refusals and canonical comparison remain;
this does not widen raw lane-entry string values.
Legacy JSON helpers share integer-only encoding and ASCII string escaping;
callers guard unsupported number lexemes before encoding.
`legacy_verify::judgment::judge` routes before lazy lane lookup, then checks the
runner, clock/inputs, lane identity and ordered Git bindings. Earlier guards
never fetch later provider resources; a supplied lane avoids the lazy lookup.
Legacy `lane_git::lane_definition` discovers definition/absent files in real Git
trees, preserving raw changed-path bytes and accepted-base existence checks.
`lane_git::lane_for` resolves accepted/branch-point lane files independently,
checks ancestry and compares canonical entries before accepted-lane validation.
Lane schema and eager resolution accept the same borrowed lossless check names.
`lane_git::required_lane` separates absent definitions from `no_lane` refusals;
all other policy/Git/canonicalization errors remain global errors, never misses.
With no lane file, resolution bypasses validation/Git reads; require-all iteration remains separate.
Legacy `discovery::input_refs` and `with_note_for` find indexed candidates and
batch note-entry presence only; neither establishes statement or signer trust.
`discovery::tree_refs` and `legacy_refs` complete tree/first-layout candidate
discovery (3f-1), including SHA-1/SHA-256 suffix identity and tag-first deduplication.
Candidate collection, trusted-check filtering and raw stale membership accept borrowed
lossless check names, including lone surrogates. Only input-ref lookup retains Python's
ASCII CHECK_NAME restriction: unsupported names find no input index, without a Git call.
This does not restrict tree-indexed records or the raw scanner's object/array/string
membership. The joined prefix still uses Python's intentionally empty owned revocation
file; it is not an external-revocation enforcement API or require-all orchestration.
`statement::statement_of` decodes and validates byte statements (3f-2b-2c), retaining
lossless Python strings, canonical integer zero and zoned ISO calendar/week clocks.
The same statement-time parser also returns exact signed UTC epoch microseconds
for later selection: offset fractions/sign, negative epochs and fractions beyond
six digits follow Python. It preserves arbitrary-codepoint separators and does
not narrow statement timestamps to chrono's RFC3339/whole-second-offset domain.
Its domain is zoned statement times, not Python parse_time's naive-date/time domain;
the existing public Clock and judgment API are unchanged.
`facts::DocumentFacts::for_check` borrows selected-check fields without narrowing
Python strings, command arguments or integer exit codes. Check names are code-point
slices, including lone surrogates; omitted inputs remain distinguishable from `{}`.
Its failed/level/time facts match Python's selection helpers, but neither extraction
nor a supplied principal establishes signature trust or authorizes a record.
`routing::route_document` shares native routing guards and kind/shard classification
without narrowing those facts. Its runner-prefix guard remains separate, after any
required lazy lane lookup; subsequent input/clock/lane judgment is not implied.
`routing::route_unconfigured` shares tier/kind/level/runner guards when rules are
absent, retaining optional versus empty caller trust levels and lossless prefixes.
No policy shard/override/lazy-lane restrictions are invented; signatures and later
input/lane/binding guards remain independently required.
`inputs::check_document_inputs` shares the native pre-lane input guard body with
lossless strings/commands and exact microsecond clocks. Its current clock is UTC
in Python's years 1..9999; datetime/timedelta overflow refuses with reason `error`.
Document judgment samples `CurrentTime` after routing/lazy-lane/runner guards,
once per reached judgment, never once per check. Native `Clock` and i64 implement
fixed sampling; `SystemClock` samples UTC on demand. Selection/configured joins
borrow the sampler across repeated judgments; native `judge(&Clock)` is unchanged.
System sampling converts signed epoch microseconds without panicking, including
pre-1970 instants; wall clocks outside Python datetime years 1..9999 refuse with
reason `error` at the reached time guard rather than authorizing or panicking.
`Failure::exception` retains non-Failure Python clock/datetime exception provenance
without adding a JSON field. Single-check output stays reason `error`; aggregate
callers must abort on this marker rather than treating it as a per-check refusal.
Ordinary policy/Git `Failure(error)` remains distinguishable from an exception.
`inputs::check_unconfigured_inputs` reuses those guards when rules are absent:
optional lossless command equality, future/age checks and exit status only.
It does not perform routing, runner/lane/binding guards, selection or authorization.
`AgeLimit::Overflow` preserves future-dated precedence for arbitrarily large ages.
`judgment::judge_document` shares selected-record lane and bound-file guards with
native judgment, preserving lazy provider reads and errors. Its caller must supply
independently verified principal/lane/hash context; it does not select candidates.
`judgment::judge_unconfigured` composes rules-absent routing/input guards with the
same lane/binding tail, preserving codepoint binding keys and native path bytes.
It enforces explicit lanes but requests no policy-level lazy lane; trust context
must be supplied independently, and candidate selection is not performed.
`Provider::blob_sha256` borrows a native `Path`, preserving Unix argv path bytes
through `LaneOnce`; implementations must not convert paths through lossy text.
Policy UTF-8 binding paths borrow this same interface without allocation.
`candidates::Prepared::new` removes passing policy shard parts and unions kind levels;
`Prepared::unconfigured` retains all candidates/order/duplicates and caller restrictions.
Both share judgment/selection. `LaneOnce` owns one lazy lane snapshot per check.
`ordering::CheckJudgment::first_valid` walks a supplied order using shared guards;
`latest_failure_after` preserves inclusive skew, first ties and lazy local-calendar
overflow refusal. `CheckJudgment::select` adds stable order/preference, conservative
failure shadowing and indexed deciding/skip metadata, not final CLI serialization.
`candidates::Levels` borrows policy sets, UTF-8 lists or lossless codepoint lists
for membership/preferences without copying. `Unrestricted` means accepted=None;
absent preferences use an empty view, not `Unrestricted`. No view verifies signers.
Event narrowing shares one lazy borrowed intersection with the existing collecting
API; borrowed result consumers need not allocate or copy an event list.
`result::Satisfied::from_decision` borrows the complete result dictionary in either mode,
including lossless command/input/event iterators and deciding/skip metadata.
Without rules it preserves caller max-age and uses policy=false, enforce=false,
sample_one_in=1 and no events. `Satisfied::write_json` emits the exact ordered successful
dictionary, including lossless fields and optional deciding/skip metadata; no final LF.
Successful views also borrow lossless check names; `CheckName::codepoints` exposes
their exact identity without using diagnostic Display as serialization.
`legacy_output` streams insertion-ordered, two-space Python JSON without an intermediate
tree, preserving surrogate code points and ASCII escaping. It adds no final newline.
`python_repr::Repr` streams Python string repr with the pinned oracle's Python
3.14.7 / Unicode 16.0.0 printability, not Rust Debug's Unicode tables.
Its generated 5,888-byte little-endian range asset is binary-searched without allocation;
the JSON provenance header pins interpreter, Unicode version and generator/input hashes.
Regenerate with the following command; append `--check` for byte-for-byte regeneration
comparison and read-only locking:
```sh
nix develop -c python3 crates/mergemaster-evidence/src/evidence/legacy_verify/gen_python_printable.py
```
Production Python before cutover is ambient/unpinned (including ubuntu-latest);
the Rust table follows the pinned differential oracle to make output deterministic.
Any ambient-version mismatch is confined to diagnostic repr escaping of code points
classified non-printable by one version, not record acceptance. Guard wiring follows separately.
`All::write_json` preserves require-all lane order and success/refusal field presence.
`require_all::write_error` emits the global envelope through `failure_json::WireError`.
Its `from_failure` and `from_policy` bridges borrow lossless core text and use only
explicit `ErrorOrigin` provenance. Exceptions emit reason `error` and class-prefixed
detail, omitting attempts/selection extras; ordinary failures preserve those extras.
Core Failure and PolicyError details share owned `NormalizedText`: scalar strings
retain their allocation, while code-point details round-trip through the lossless writer.
Its Display is diagnostic-only; scalar-only serde refuses code-point storage.
`ErrorOrigin` distinguishes Failure from Exception with a mandatory class in both
core error carriers. `CurrentTime` returns typed `ClockException`, preserving class
and lossless detail through judgment and global aggregate aborts, never inferring
the class from a message. The wire bridge preserves that class without text inference.
Lane and declared-path diagnostics preserve borrowed Python code-point contexts;
their missing/shape/argv/path reasons and details follow the pinned source.
Invalid path text uses the pinned Python repr primitive, not Rust Debug.
Policy-header refusals and lane branch-point mismatches also preserve check code points
and the pinned diagnostic text. The former u64 max-age bound divergence is closed:
Python's wide positive integers are accepted through owned decimal seconds until
datetime arithmetic, where exact OverflowError texts match the pinned source.
Out-of-range floats and wide integers each keep their own provenance-backed
refusals from the original lossless document source.
Nested kind/level and other judgment construction follow in separate module slices.
Command/base/value helper contexts are borrowed lossless fragments. Direct missing
command and unhashable input-order members preserve KeyError/TypeError provenance;
outer kind/level missing-command guards remain ordinary policy failures.
Outer kind guards use pinned Python repr and exact trust-level/runner-prefix details;
truthy non-map by_level values retain explicit AttributeError rather than Failure.
Level override invalid/unlisted/lane refusals use the exact pinned by_level repr text.
Shard-part no-record refusals build the check name losslessly through the shared
borrowed name type; attempts count only the removed passing shard parts.
Prefix miss-scan refusals (degraded, untrusted, wrong_check, stale_tree,
no_record) carry the borrowed check name with exact Python code points.
Conservative selection's newer-failure detail also carries the check name losslessly,
without changing its pinned commit/level wording or failure precedence.
Judgment lane/digest and bound-input refusals use the pinned details; changed paths
and native binding paths preserve Python's surrogateescaped filesystem bytes.
Routing's shard-failure, tier, unsupported-kind and signer-level refusals retain
the pinned details, Python repr and lossless check/runner/tier/kind-list code points.
Input guards spell check-failure exits without integer narrowing, retain borrowed
check names in exit/command refusals, and include the exact seconds in age refusals.
Duration overflow messages distinguish the bounded day-count and C-int overflow
buckets exactly; current-plus-skew overflow retains Python's date-range message.
Lane-provider Failures surface without attempts metadata, as lane_for raises
and lane_once propagates them; in-judge raises keep the ambient count. The
pinned module's blob_sha256 catches git-level Failures itself, so provider
exceptions still propagate while missing files read as absent.
Value-rule, shard and base-input payload names ride the widened normalized text
storage, so surrogate-escaped policy keys stay lossless end to end, decoded
directly from the original policy text with no serde re-encoding bridge.
Header, command/base, kind, value-rule and level validation borrow that same
lossless statement document. Policy seconds have owned decimal payloads and a
lossless integer writer; max_age_s=2**64 (and wider) is accepted exactly like
Python, with the pinned later OverflowError texts.
Binding paths retain normalized text until the blob read, after earlier guards.
The Git provider uses UTF-8 surrogateescape at the tree:path argument boundary;
UnicodeEncodeError positions include the tree prefix, with exception provenance
and no attempts metadata.
Nested surrogate payload keys/values are decoded losslessly from the original
policy source, including kind/level/command/input-order/shard identities; the
four-case nested identity oracle fixture pins that domain as ported. Statement
payloads (observed records) are a separate domain, still scalar-only until the
legacy statement port slices decode their bytes with the same code-point source.
Failure attempts distinguish `None` (absent) from `Some(0)` (explicit zero).
Exceptions and prefix misses retain absence; degraded records retain their explicit
count. Zero normalization is confined to existing oracle-test transports, not wire output.
Source-provenance threading/diagnostic parity must land before CLI wiring. Members/log
extras remain with those ports; discard partial output on error.
`configured::required` joins trusted collection and existing configured selection
for one required check, returning the selected owned trusted record. Each call owns
a fresh collector budget; rules supply projection inputs, with no crate binding,
run inputs, preferences or level-lane callback. Eager lane resolution and per-lane
refusal/aggregate decisions belong to require-all orchestration, not this helper.
`configured::required_git` uses sanitized Git to stream bound blobs into SHA-256
with byte-preserving paths and discarded stderr, without a blob-size allocation.
Python maps Git OSError, nonzero status and its 60-second timeout to no blob.
Rust maps process/read/status/timeout failures to no blob; hashing stays streamed.
Shared `gate::git::git`, `git_bounded`, projection exchanges, bound-blob hashing
and note discovery each use one 60-second child-lifetime deadline through final wait,
with discarded stderr and nonblocking pipe I/O. Existing output bounds and strict
projection OID/status validation remain unchanged; timeout is reason `error`.
Linux final waits use `pidfd_open` plus blocking `poll` (Linux >= 5.3), retaining
the same absolute deadline and direct-child kill/reap semantics. Interrupted polls
recompute the remaining deadline; no sleep or periodic child-status polling is used.
Unsupported pidfd syscalls propagate existing I/O errors without fallback. The hosted
CI matrix covers Linux only; other platforms retain their existing wait behavior.
`RawBatch` uses one deadline across every request and final EOF/status validation;
neither a successful reply nor finish renews it. Expiration cancels the owned child.
Note discovery likewise shares one budget across all requests, preserving order and
duplicates or returning an error with no partial candidate list.
Native batches share that lifetime rule; signing passes its Python-compatible
300-second blob-content timeout, while native digest/validation batches use 60.
Deadline failures propagate as errors, never partial contents/digests or validation
success; framing, streamed hashing and direct-child cleanup remain unchanged.
The native evidence Git helper polls stdin/stdout/stderr together under one explicit
deadline, preserving binary stdout and nonzero-status diagnostics without threads.
Observation blob/tree/commit creation uses 300 seconds; verifier and native-only
metadata/publication calls use 60. Timeout errors include stderr captured so far.
The shared capture engine accepts a retention sink while keeping one child/deadline;
the default native sink retains the original byte-for-byte stdout/stderr behaviour.
Generic wrapper output storage and origin publication use 600 seconds per Git
spawn, matching evidence-wrap. Timeout propagates as an error without publication
success or a stored-output identifier; lane execution itself is unchanged.
Signer source-pack export and scratch import each get their own 300-second lifetime
deadline; stderr stays inherited, export stdout is retained and import stdout is
discarded. Expiry is an error, not a partial export or successful import.
Gate ancestry probes use 120 seconds per spawn, matching ci-evidence-gate's Git
runner. Exit 0/1 keep their distinct ancestry decisions; expiry is an error,
not an unrelated-history or foreign-merge verdict.
Timeout/error/drop kills and reaps only the direct child, as Python POSIX does.
No process group or signal forwarding is added; terminal SIGINT stays inherited.
A grandchild can outlive timeout and hold pipes, but cleanup does not wait for EOF.
Intentional no-deadline exceptions preserve Python parity: parity-drift's reporter
Git calls (pinned scripts/parity-drift:33-37), its native default-root lookup for
tool consistency, and keygen's scratch Git init (independent pinned oracle
`scripts/evidence-keygen:55-56,135`, not a working-tree executable).
A deadline for those paths would need a separately approved divergence.
The protected CI fetch instead retains its existing external `timeout` wrapper:
30 seconds with a 2-second kill-after, not a GitChild deadline. Direct Git fixture
setup under tests is outside this production deadline inventory.
`require_all::require_all` validates sorted lossless names before off-skip, resolves
eager lanes before verification, and returns a complete typed summary or a global
error, never partial results. Only eager `no_lane` is per-lane; explicit verification
failures (including Git `error` and `record-budget-exceeded`) remain per-lane, while
marked non-Failure clock/datetime exceptions abort globally. Each check owns a fresh
collector, so a budget refusal cannot poison later checks. Decisions aggregate
reject before would-reject before ok; empty checks are satisfied.
A missing validated tier is a global internal-invariant PolicyError, never a panic.
Its private clock seam tests that a later sampling exception or timedelta overflow
discards earlier successes; production uses the same reached-judgment SystemClock path.
Joined rules-absent parity tests use actual SHA-1/SHA-256 trees, SSH-signed notes,
signature partition and Git blob reads through selection/result conversion, including
Unix non-UTF-8 binding paths, lossless keys, skips/preferences and refusals.
`configured::retained_detailed` also retains the complete deciding-record and
skipped-newer metadata on selection refusals; preparation failures have neither.
The simpler retained/verified interfaces intentionally return only the failure.
`legacy_policy::check_names` enumerates sorted lossless policy names and selects entries
by borrowed code points, including lone surrogates. It shares the existing root/entry
parser without adding statement byte/depth caps; raw string controls are refused,
while escaped controls remain valid. Enumeration does not evaluate policy.
`PolicyDocument` also accepts borrowed code-point names through full header/kind/level
validation and placeholder normalization, without narrowing names to a regex or UTF-8.
Normalized policy commands/runner prefixes now own scalar or lossless code-point text
and borrow the same input/runner guards. Placeholder replacement preserves code points.
The logical CLI repository name also stays borrowed lossless text through
kind/level replacement and `require_all_cli`; native string callers still work.
Dispatch must use compiled member APIs, never `crate_sources::AcceptedSource`
or `json_bytes::parse`: their outstanding capture/byte/depth prerequisites
remain binding before any production caller becomes reachable.
`legacy_verify::policy_loader` reads policy bytes from the supplied Git revision,
strictly decodes UTF-8, then invokes `PolicyDocument`. This is the first production
caller; the C1 loader precedes any CLI/dispatch wiring. Inherited `.fractal` preference
and exact Git argv are retained for unresolved revisions as well as full OIDs.
`cli_config` shares that inherited config-path/blob transport with policy ingress.
CLI lane-file reads preserve strict UTF-8, exact no-readable-lane refusals and
unresolved revisions; native lane discovery and its OID guards remain unchanged.
Invalid bytes/config-read Failures map to `no_policy`; a UTF-8 BOM decodes and is
refused by JSON instead. Real-Git SHA1/SHA256 oracle cases bind invalid bytes, BOM,
NaN, negative zero, overflowing floats and Infinity acceptance/refusal text.
The current serde view still serializes scalar text only; lossless JSON output
remains separate from typed require-all orchestration. Other raw policy fields retain
their existing serde-value domain; this name-boundary port does not widen those fields.
`statement_bytes::decode_json_bytes` ports Python's BOM/NUL-based UTF-8/16/32
transport detection and surrogatepass decoding (3f-2b-1), retaining code points
including lone surrogates rather than replacing them with invalid Rust strings.
`statement_tokens::Tokens` ports lossless strings and numeric literals (3f-2b-2a),
including lone surrogates, nonfinite floats and the 4300-digit integer limit.
`statement_document::Document` adds iterative container grammar and ordered keys
(3f-2b-2b), preserving duplicate-key position, rejecting extra top-level data and
owning deeply nested values without recursive drop. Overwritten values remain
unreachable in its private arena until document drop. The statement entrypoint
refuses blobs above 1 MiB before parsing (a Rust-only guard; Python has no cap).
The document parser also caps nesting at 256 containers, including the root and
empty arrays/objects. Byte-statement and record APIs return `statement-too-deep`
above that depth. This is a deterministic, fail-closed guard before the owned
cache port: Python's end-to-end deepcopy fails at interpreter-dependent depths.
Depth does not bound arena node count; the 1 MiB statement-byte cap bounds nodes.
The uncapped general-purpose `Document::from_text` API remains separate from policy
ingress. Approved fail-closed policy-JSON resource divergence: `from_policy_text`,
used inside `PolicyDocument::parse` and name enumeration, checks 1,048,576 source
bytes before Tokens allocation, combined object/array depth 256 (including root
and empty containers), and 262,144 nodes before value allocation (including
overwritten duplicates). These bounds are stricter than CPython's resource-dependent
`RecursionError`, replacing the prior unbounded-policy-JSON label. Typed resource
causes survive in `PolicyError.resource`, with ordinary Failure/error and no prefix.
Text-taking `check_names::selected` and `require_all::require_all` cannot bypass them.
The separate input-JSON divergence below and bounded statement ingress are unchanged.
Native-library lane-file `check_names` fields retain their serde-value domain.
This caveat does not authorize narrowing the CLI's lossless lane-file surface.
Library-only invariant refusals have no Python counterpart: manually constructed
malformed validated-record primitives return `error` / Failure with
`invalid validated statement` (no attempts). These states are unreachable through
statement ingress.
Approved fail-closed TOML resource divergence (#257): Rust checks the 1,048,576
source-byte cap before allocating/parsing, rejects combined array/inline-table
depth above 256, and charges at most 262,144 nodes before allocation (including
the root, implicit namespace tables, containers and scalars). These bounds are
stricter than CPython
3.14.7 (first `RecursionError` at 498 arrays / 332 inline tables). Resource errors
are typed Rust errors, mapped at manifest ingress to ordinary Failure/error with
the existing `<manifest path>: ` prefix. They do not imitate Python exceptions.
`MAX_KEY_PARTS=1000` and its actual Python exception path remain exact.
Full-document tomllib comparisons also cover dotted-key/header flag timing and a
1000-part header followed by a 1000-part key, preserving all 2000 nested parts.
`crate_inputs_text` preserves Python's strict UTF-8 decode diagnostics and POSIX
join/normpath semantics, including empty directories and exactly two leading slashes.
`crate_inputs::TreeSource` reads committed manifests using Python's inherited Git
environment; its member-verifier mode sets only `GIT_NO_LAZY_FETCH=1`.
Configuration prefers `.fractal` over `.st`. TOML decode refusals retain their path;
integer-limit and key-part-limit exceptions propagate without a path prefix.
`crate_manifest_ops` preserves Python truthiness, attribute and path operations on
typed TOML values; non-table dependency specs remain ignored as in the oracle.
Approved diagnostic divergence: uncaught manifest-operation exceptions retain the
final `Class: message` and exit status, but Rust does not reproduce Python traceback
frames. Their structured library origin remains Exception, not Failure.
`crate_layout` discovers literal and terminal-`/*` workspace members and patch paths.
Approved acceptance narrowing: a present non-string `package.name` refuses with
`error` / Failure and `<manifest path>: package.name is not a string`.
Cargo rejects such manifests; Python's mixed-key collisions, NaN identity and
sorting behaviour are deliberately not reproduced. This text has no Python-parity
claim. Committed coverage: `crate_layout_tests::layout_and_type_confusion_match_oracle_except_approved_names`
asserts all12 approved non-string refusals and compares ordered member pairs for
all96 cases, including duplicate-name replacement, root prepending and Git's
core.quotePath C-quoted wildcard names.
Crate-key oracle fixtures separately preserve insertion order and list-valued
declared paths, including empty workspaces, all-excluded None keys and nested-list
TypeError parity. CLI require-all retains lossless lane-base text through its
validation boundary; the native lane-base interface stays unchanged.
Oracle tests share a lazily resolved Python3.14.7 interpreter, checked once for
the exact version and optimization level0. Each shared-helper launch uses `-I`
to ignore Python environment/site overrides; fixture-local assertions remain.
This includes integration oracle harnesses and nested oracle subprocesses.
Synthetic pipe/deadline children and ZIP fixture writers are not oracle callers.
Record depth fixtures retain their inputs with oracle recursionlimit10000, not
an asserted stack-dependent497/498 RecursionError boundary. Rust's deterministic
resource refusals remain unchanged;100k TOML depth rejection is Rust-only.
`crate_closure` walks normal/dev/build and target-specific path dependencies with
an explicit stack. Its memoized cycle unions, eager target lookup and lazy
per-table dependency evaluation preserve the pinned Python walk's ordering.
Approved fail-closed closure resources (separate from TOML container depth):
at most256 uncached active manifests, counting the starting manifest, and1024
distinct uncached manifests per shared operation cache, charged before reading.
Cache/cycle hits neither descend nor charge. Typed Failure/error texts are
`path dependency depth exceeds 256` and `path dependency crate count exceeds 1024`.
The count bounds memoized reachability to about1M set entries (roughly64–128MiB
for short paths, plus path-length/allocator variation), not an absolute byte cap;
4096 crates would permit about16M entries.
`crate_input_document::Inputs` retains the accepted-base input JSON losslessly,
validates root/global/crates/no_tests shapes and never downgrades malformed new config.
Approved resource-dependent divergence: CPython `json.loads` can raise
`RecursionError` on nested `rust-test-inputs.json`, depending on stack/caller depth;
Rust imposes no depth cap or stack-boundary emulation. A 100,000-depth ignored
metadata fixture accepts in Rust without assuming a CPython stack boundary.
Approved fail-closed resource divergence: crate inputs share the policy parser's
pre-allocation node charge (root, containers, scalars and overwritten duplicates),
limited to 262144 nodes with typed Failure/error
`crate inputs JSON node count exceeds 262144`. Limit/+1 shallow oracle cases
and Rust-only deep boundary cases cover this independently of CPython recursion.
CPython may accept the same nested shape or raise RecursionError depending on its stack.
`crate_paths` assembles globals, all member manifests, patches, dependency closures
and per-crate extras without encoding lossless paths. Unreviewed crates declare `.`.
Approved class/origin AND diagnostic-text divergence: mixed non-string path
elements raise Python TypeError / Exception with hash-seed-dependent sorting
text, but Rust returns `error` / Failure with
`.st/rust-test-inputs.json: declared path is not a string`; acceptance is unchanged.
Deterministic iteration/unhashable-element exceptions keep Python's class and text.
Evidence: `tmp/crate-path-shapes/seed-results.json`.
`cli_signature::signature` separately preserves the oracle's inherited Git
programs/environment and exact argv, including configured non-SSH verifiers.
It accepts raw key/revocation paths without native prevalidation. Signature
stdout uses the approved RawBlob 1 MiB cap with original commit identity:
`{commit} exceeds 1048576 bytes`, typed Failure/error, early abort and kill/reap.
Strict UTF-8 failures retain the Python exception class/text. Native signature
hardening is unchanged; hidden dispatch selects this explicit CLI primitive.
`records::read_statement` adds bounded Git capture and record layout/parent/subject
checks (3f-3a), with `statement-too-large` distinct from malformed-record refusal.
Missing subjects are allowed without lazy fetch. `records::RecordCache`
is constructed per candidate/check with `for_check`, with exact repo/commit/optional-tree keys.
`records::read_statement_cli` separately injects oracle transport; native/cache defaults stay unchanged.
Listing/statement/commit keep existing 1 MiB caps/texts with early abort; only the subject probe sets no-lazy-fetch.
Approved fail-closed divergence: subject output above 128 bytes aborts with `Git output exceeds 128 bytes`; Python would compare oversized output with the tree.
Ordinary Git Failure means absent; successful invalid UTF-8 raises Python's UnicodeDecodeError.
`RecordCache::for_cli_check` fixes the transport for its entire ownership lifetime;
the original cache/ownership matrix runs in both modes without mixing entries.
The exact-unit, one-unit-over and negative-entry budget boundaries also run in both cache modes.
`cli_discovery` uses the same bounded-record streaming ref sink with insertion
order; existing log callers retain their BTreeSet sorting. Listings stay uncapped
as streams, without whole-output retention; prefix order and first-seen IDs survive.
CLI note presence uses one inherited `cat-file --batch-check` and incremental strict
UTF-8 rows with no whole-output cap. Approved fail-closed divergence: headers over
138 bytes including LF return `note Git header exceeds 138 bytes` (Failure/error).
Only full lowercase OIDs enter this API: the largest missing echo is 64+1+64+8+1=138
bytes; normal headers are at most 93 bytes. Native note discovery is unchanged.
Immutable `Arc` documents are interned per repo/commit; member hits are free and errors uncached.
Observed records already flow through the lossless `Document`, cached `Arc<Document>`
and borrowed `DocumentFacts`; no serde-value conversion intervenes. Real SHA-1/SHA-256
records in UTF-8/16/32 compare complete tagged values and selected input/command
codepoints against Python, including lone surrogates, wide integers and float bits.
Limits: 4,194,304 units and 8,192 entries; `record-budget-exceeded` latches and aborts the check.
Units charge two/node, four/object entry, two/cache entry, one/text point,
integer digit, array index or key byte: a conservative 128 B/unit retained-allocation
envelope (~512 MiB), not RSS. Charging occurs after parsing. Excluded transient:
a 1 MiB flat array needs up to 524,288 nodes (36 MiB at 72 B/node), 4 MiB indices,
4 MiB decoded text, 1 MiB input and up to 1 MiB scalar payload; arena growth adds
18 MiB (~64 MiB total, ~70 MiB at Node<=80 B). Allocator/runtime overhead is extra.
Loader errors, including either cap refusal, abort the whole check rather than
skipping a record. `signature::signature` ports Git SSH status/principal inspection
(768-773), overriding repository signature programs and using explicit signer and
revocation files. It requires a readable regular revocation file before signature
status work (symlinks to valid files allowed); absent, dangling, directory and
no-read-bit paths refuse. Relative policy paths resolve once from Git's worktree
root, or from the supplied directory in bare repositories, then the same absolute
path is checked and passed to Git. This does not prevent policy mutation between
check and use. Missing policy refusal is fail-closed against Python until fractal#6429
is resynced. Returned statuses are not
authorization: selection (3g) and require-all (3h) remain; candidate indexes and
structural records establish no trust.
`collection::CandidateCollector::for_check` owns the shared cache across member calls.
`for_cli_check` fixes oracle ref/note/cache transport for that collector's lifetime;
`prefix::candidates` follows its mode for signature partition and stale misses.
It ports ordered structural candidate gathering (957-981), input-key projection,
and default crate/key equality, not test-count policy or signature authorization.
Any load error aborts collection without returning a partial candidate set; budget
exhaustion remains latched even for later calls with no matching records.
`trust::partition` preserves ordered trusted/untrusted/degraded groups (982-995):
only G with a nonempty principal equal to the statement signer is trusted; B/N
is bad_signature, other mismatches untrusted_signer, and degraded skips signatures.
`trust::partition_cli` shares that partition logic but injects the oracle signature
transport and raw filesystem key/revocation paths; the signed SHA-1/SHA-256
partition matrix compares both modes against the original Python grouping.
Policy/Git errors abort without returning partial groups. Check selection and
miss precedence use `prefix::candidates` (996-1008), not final check authorization.
It owns an EMPTY revocation file like Python957, not caller revocations; never use
this prefix for an API promising external revocation enforcement.
The CLI owns its empty revocation file through `cli_tempfile::TemporaryFile`,
with mode 0600, Python's temporary-directory search order, raw filesystem paths
and exception provenance. Drop unlinks it on success and early failure; the
native tempfile/canonicalization path is unchanged. The same owner supports
the `.keys` and `.log-keys` preparation suffixes before dispatch composition.
`cli_keys` separates signer preparation from later shadow-log preparation so the
dispatcher can preserve main's early project/require-all returns and run-input
ordering. Signer temporaries precede config reads; log temporaries follow reads.
Explicit signer paths use lexical abspath/isfile; absent log config preserves
explicit log keys. Owners remain alive through verification; explicit signer
`close` runs after capturing any result, with cleanup errors taking precedence.
CLI prefix revocations also explicitly close after capturing collection/partition
results, preserving close-error precedence on both successful and failed paths.
Shadow-log signature revocations use that same owner and close immediately after
the signature subprocess, before decoding its result, matching Python's context.
`raw_batch::RawBatch` provides scanner-specific one-request exchanges, 128-byte headers
and pre-read 1MiB body limits; explicit finish validates status, errors/drop kill and reap.
`projection_capture::raw_batch` is the CLI batch prerequisite: one complete request
set through the shared collector, retaining bounded 128-byte headers/1MiB bodies.
A false consumer result disables later body parsing/retention/caps while draining
under the same deadline and validating Git exit/stderr; native batches are unchanged.
`stale::other_trees_have` scans raw notes for check membership, not trusted statements.
Reached 1MiB/depth256 overflow refuses; a true match stops before later body reads.
CLI stale misses use exactly two complete inherited `cat-file --batch` invocations:
all tree frames first, then blob frames. After a JSON match later bodies are discarded
without retention/parsing/body-cap refusal, while status/stderr/deadline still apply.
`configured::CliGitProvider` separately supplies inherited oracle hash-only reads:
uncapped streaming stdout, the existing owned deadline, and no native sanitizer.
Explicit `configured::Transport::Cli` joins select that collector for detailed
single-check selection/log overlays and member aggregation; native wrappers keep
their defaults. `required_git_cli` also selects the CLI hash provider, and
`require_all_cli` uses CLI lane resolution and required-check collection.
Member aggregation creates one collector in the selected transport before its
member loop; retained records share that check-wide budget, and exhaustion aborts.
These library joins do not install a binary dispatch or prepare CLI tempfiles.
Pinned selector stress coverage includes empty keys and dotted empty selectors,
64/96 repeated declarations, and preferred/legacy aliases resolving to one
selected identity, comparing complete selected bytes and projection keys.
The public prefix request and CLI require-all entry carry signer filenames as
raw `Path` values. CLI signature partition never narrows them to UTF-8.
The native partition deliberately refuses newly representable non-UTF-8 signer
paths as Failure/error `allowed signer path is not UTF-8`; this approved
native-only fail-closed divergence preserves the native signature API.
Member/explicit allowance and member-project policy-base carriers retain original
`TextRef` codepoints through bare rust-test-keys reads and inherited verifier
reads, preserving surrogateescape argv, original source identities and exception
offsets. Repository NUL validation precedes later revision conversion.
Lane discovery uses the gate's sanitized Git command and rejects malformed or
unterminated ls-tree rows; shared subprocess timeout/output bounds remain open.
`workflow::workflow_job` selects exact generated-workflow text and transitive
job dependencies; it follows the legacy layout contract, not general YAML.
Workflow refusals name the missing dependency, or quote the stripped offending
line's first 60 code points with Python repr, rather than a generic layout error.
`selection_json::select_json` preserves legacy integer JSON selections. Selected
floats, JSON extensions and nesting above 127 containers refuse with named
`input-selection-*` reasons; extension diagnostics identify the token and byte offset.
`selection::selected` resolves the preferred `.fractal`/legacy `.st` layout at
the supplied Git tree and reads strict UTF-8 there, never from the checkout.
Malformed JSON (including integer digit-limit refusal) reports the unquoted
resolved file path followed by ` is not JSON`; invalid UTF-8 reports ` is not text`.
Selection/projection oracle failures compare complete diagnostic text, not just reason.
Selected blobs above 16 MiB refuse with `error` before decoding or selection.
Byte captures stop at limit + 1 and kill/reap the direct child rather than
draining unbounded stdout; the existing `Git output exceeds {limit} bytes`
diagnostic is unchanged. Boundary and endless-writer fixtures cover the 16 MiB
selection limit and zero/small limits. Selected policy-value oracle fixtures
compare top-level finite/infinite float bits and signed zero, with a dedicated
NaN tag (NaN is not equality-comparable); only the original huge-float skip remains.
`projection::project` computes legacy reduced Git-tree keys, retaining raw names,
symlink/gitlink modes and canonical selector entries; empty projections have no key. Selected reads require full tree OIDs.
Projection validates full tree OIDs before fast paths and ends Git option parsing.
Its reads and write plumbing inherit the environment with the verifier's fixed Git
defaults and use the shared draining collector; the native sanitizer is unchanged.
An alternate-object fixture covers listing, preferred config resolution and selected blobs.
Projection rejects embedded NUL only when reaching subprocess argv, with Python's
`ValueError: embedded null byte`; whole-tree fast paths still skip unused plain names.
The shared binding-path encoder supports strict UTF-8 and filesystem surrogateescape
without copying scalar storage, preserving exact UnicodeEncodeError runs and offsets.
The stdout/OID guard is an approved fail-closed resource divergence: pinned
`scripts/evidence-verify:75` captures stdout without a byte cap. Git is a trusted
environment binary; compliant write plumbing emits one OID, not arbitrary keys.
`projection_process_error` supplies Python subprocess exception formatting for
the replacement transport: errno/filename text and full lossless argv repr for
timeouts. Its fixtures exercise missing executables and expired deadlines.
`projection_oid` supplies an incremental decoder for the replacement transport:
Python whitespace is stripped with at most 65 retained OID bytes, including
100k padding and byte-split Unicode whitespace. Bare OIDs need no final newline.
The31 oracle fixtures retain all25 strip cases plus uppercase, embedded NUL and
CRLF at both OID widths. Tests exhaust short-input split points and sample64
deterministic chunk partitions per fixture, including the200k padding inputs.
The approved trusted-Git fail-closed guard rejects malformed keys Python accepts;
evidence: `tmp/projection-stderr-oracle/stdout-parsing.json`. Python has no cap at :75.
`projection_capture` drives project's reads and writes, including a real noisy-fsmonitor oracle fixture.
It drains stderr while retaining 1 MiB: success stays accepted at any stderr volume.
Nonzero overflow refuses with `Git projection stderr exceeds 1048576 bytes`;
otherwise Python's stderr diagnostic and operation-prefixed process errors survive.
This is an approved resource divergence: Python has no byte caps at oracle :75.
The exchange's 60-second deadline matches that same line; update-index stdout is discarded.
Linux collector fixtures cover signal death, stdout/stderr EOF before delayed exit,
and broken-pipe cancellation, checking that each direct child is reaped.
An early-drop fixture checks the same collector-owned `GitChild` boundary.
Whole project listings, selector configuration listings and selected-content
existence listings have a separate approved 64 MiB whole-collection cap.
The shared collector stops at limit + 1, cancels/reaps, and returns typed
Failure/error `{exact tree} exceeds 67108864 bytes`; Python has no listing cap.
The larger budget accommodates measured real listings (dotfiles origin/main
`c2a85650da041b292a2bbc5c36eafb139cee046f`: 1,825,987 bytes).
`projection::listing_capture_tests` compares all three paths with the pinned
oracle at 67,108,864 and 67,108,865 bytes; only Rust rejects the latter.
`utf8_stream::Utf8` supplies strict incremental decoding with at most four
pending bytes, retaining the first Python decode error and its whole-stream
byte offset. Its split-boundary matrix compares 10,773 pinned-interpreter
samples, including truncated sequences and malformed bytes after earlier rows.
Shadow-log ref enumeration uses this decoder inside the shared cancellable
collector, with no whole-stream cap or retained listing. Each record retains at
most `prefix.len() + 129` UTF-8 bytes: longer records cannot match and are
discarded while strict decoding continues. Python splitlines boundaries and
Git-failure-before-decode precedence are preserved. Only distinct matching IDs
are accumulated; a 64 MiB + 1 malformed record is accepted/ignored like Python.
The shared nonblocking collector also has an explicit no-timeout entry for
rust-test-keys source reads. Source overflow cancels/reaps the direct child
without waiting for EOF from descendants holding inherited pipe descriptors.
`TreeSource::git` bounds workspace/configuration metadata stdout to 1 MiB,
and configuration stderr to 1 MiB; overflow kills and reaps the child and
returns Failure/error `{exact revision argument} exceeds 1048576 bytes`.
This approved RawBlob resource divergence also applies to nonzero configuration
stderr, never emitting a truncated diagnostic. Wildcard member stderr is ignored.
These rust-test-keys reads retain inherited Git settings and no timeout.
CLI configuration lookup and standalone no-test allowance reads also use the
approved 1 MiB RawBlob capture: exact revision for lookup metadata, exact
`base:path` for allowance bytes, with their existing verifier Git transport.
Generic configuration blob resource identity concatenates the original lossless
revision and resolved layout path, never decoding re-encoded subprocess argv.
Real-Git SHA1/SHA256 boundary fixtures preserve adjacent DCC3/DCA9 surrogate
code points in the complete typed source/detail, although those argv bytes
resolve the same Git ref as scalar U+00E9.
`log_transport::read` separately ports shadow-log `no_lazy`: inherited environment,
fixed SSH Git settings, no lazy fetch/replacements, LC_ALL=C and a 60-second deadline.
Nonzero Git status is data except source overflow; stdout has the approved 1 MiB
RawBlob capture budget, using exact `head:path`, revision expression or head.
Overflow stops/kills/reaps at limit + 1. Stderr remains drained/discarded.
Spawn/NUL/timeout exceptions retain Python class and text with no operation prefix.
`log_lines::read` reads record IDs after the last GC marker, with replacement
UTF-8 decoding and Python line/word whitespace. Real-Git SHA1/SHA256 oracle
comparisons cover malformed records, GC ordering and absent blobs.
`log_age::total_seconds` rounds the exact integer microsecond ratio once, ties
to even, matching CPython timedelta rather than converting to float first.
Oracle comparisons cover complete f64 bits and integer ages at rounding
boundaries, signed neighbours, large values and i64 endpoint differences.
`log_view::read` judges the signed log head and returns absent/unsigned/stale,
missing, unlogged-pass or ok metadata with exact age and missing counts. Signed
SHA1/SHA256 fixtures compare the entire view with Python, including clock edges
and input-key indexes. `members_log_view::read` adds sorted per-member key reads,
deduplicated missing counts, first-five unlogged summaries and oldest readable
time. Invalid times clear the summary before mixed naive/aware times can raise
Python's exact TypeError. `members::verified` accepts optional log keys and overlays
the full member view on success or uncovered refusal, retaining every original key
and using no chosen records on refusal. Preparation errors/exceptions stay unadorned.
`configured::verify` adds the single-check optional log overlay, retaining complete
failure selection metadata. Shadow-key projection precedes verification, swallowing
only ordinary projection Failure, never Exception; crate keys bypass projection.
Empty log keys disable decoration. CLI wiring remains separate.
Member times remain lossless code points through parsing, lexical tie-breaking
and the JSON field writer, including lone-surrogate ISO date/time separators.
Log readers preserve lossless check names through comparisons and filesystem
surrogateescape argv encoding; invalid surrogates and NUL retain exact Python
exception class, text and evaluation order.

### Main-push tree-equality evidence

`gate --event push` explicitly allows a signed PR-head observation to satisfy a
default-branch push with the **same Git tree**, including squash and merge
commits. The default remains `pull_request`, with exact commit matching and the
protected-base merge restriction above. BASE lanes must opt in with
`"events": ["pull_request", "push"]`; PR author policy does not authorize pushes.

Use a read-only, parent-owned bootstrap: load the verifier pin, keys and lane
policy from the main commit's **first parent**, never from the pushed candidate.
Fetch the main commit, its parent and evidence Git objects without executing
candidate source. For example, after provisioning the BASE-pinned verifier:

```sh
git fetch origin 'refs/notes/evidence/*:refs/notes/evidence/*' \
  'refs/tags/evidence/*:refs/tags/evidence/*'
BASE="$(git rev-parse "$GITHUB_SHA^1")"
mergemaster gate --event push --check example --base "$BASE" \
  --head "$GITHUB_SHA" --event-file "$GITHUB_EVENT_PATH" --format json
```

Evidence is indexed by tree in `refs/notes/evidence/<tree>/<record>` (or retained
evidence tags); the signed subject identifies its original commit. No PR lookup
or mutable PR association is needed. The gate recomputes every lane, environment
and workspace binding from accepted BASE policy and the main tree. Existing
signature, trust, age, newest-failure and freshness/reuse requirements still
apply. Protected edits are refused even with human-approval policy.

A push event file and authenticated GitHub read access are required. Immediately
before decision publication, the gate checks the live repository default branch
and requires event `after`, requested HEAD and the live branch SHA to agree.
Refusal reasons include `tree_mismatch`, `event_not_allowed`,
`not_default_branch`, `stale_push`, `no_parent` and `base_not_parent`.
Pull-request live rechecks use `stale_base`, `stale_head` and
`pr_metadata_changed` as described above.

### Protected edits with human approval

A lane may set the following policy in the accepted BASE `lanes.json`:

```json
{
  "protected_edits": "human_approval",
  "approvers": ["schickling"],
  "require_hosted": [{
    "name": "validate",
    "workflow_id": 123456,
    "workflow_path": ".github/workflows/validate.yml"
  }]
}
```

Replace the example workflow ID with the repository's actual workflow ID.
Both approvers and hosted checks must be nonempty. An approver's current
approving review must have `commit_id` equal to the exact candidate HEAD.
New pushes invalidate prior approval; dismissed approvals and later change
requests revoke it. The required hosted job must have completed successfully
at that same HEAD in a `pull_request` run whose numeric workflow ID **and**
workflow path equal BASE policy. A matching job display name is insufficient:
renamed workflows and extra PR-authored workflows named `validate` do not count.
Every configured hosted check is required. This administrative path passes
without an agent evidence note and does not activate candidate policy.

The publisher fetches authenticated evidence into a fresh trusted file and
passes `--hosted-evidence FILE`. The approval evaluator performs no network
requests and never executes candidate code; the existing final live PR/base
recheck remains mandatory. The file has version 1, `repository`, `head`,
`reviews` (projected API review ID, user login, state, commit ID, submitted time),
and `checks` (job name, head SHA, status, conclusion, and an API-joined
`workflow_run` with run ID, workflow ID, path, head SHA and event).
Never accept this file from PR artifacts, checked-out candidate files, or an
untrusted caller. The generic publisher fragment collects all API pages.

**Limit:** when the PR edits the validate workflow itself, validate executes
that changed file, not BASE's contents. The decision summary explicitly says:
“this PR changes the validate workflow; validate ran the changed file”.
Workflow identity prevents name spoofing, not a human-approved change to the
authorized workflow's implementation. Reviewers must inspect such changes.

## Generic lane execution and signing

`mergemaster evidence wrap` runs the exact BASE-declared command once, measures
its inputs before and after execution, signs successes and failures, imports the
immutable signed note and explicitly pushes its note ref to `origin`:

```sh
MM=/absolute/path/to/mergemaster
CONFIG="$HOME/.config/mergemaster/evidence-sign.json"
"$MM" evidence wrap --check graph-full-check --base "$BASE" --config "$CONFIG" \
  --signer "[\"$MM\",\"evidence\",\"sign\",\"--config\",\"$CONFIG\"]" \
  -- tools/graph check --full
```

### Signed repository identity

Pass `--repository compoundingtech/factory` to bind the logical repository to
the signed statement. The identity is a literal `OWNER/NAME`: each component
is nonempty ASCII alphanumeric, `-`, `_` or `.`, excluding `.` and `..`.
Comparison is case-sensitive; URLs, checkout paths and Git remote configuration
are not identities and are never used to infer one.

The signed JSON statement carries an optional top-level `"repository"` string,
alongside `_type`, `subject`, `predicateType` and `predicate`. It is covered by
the record's existing signature, independently of the subject commit/tree and
input digests. `Request.repo` remains only the local source path;
`Request.repository` carries the explicit logical identity to the signer.
This is a repository-bound evidence statement, not an authorization to sign
arbitrary Git objects. The existing SSH signing namespace remains `git`.

Operator-owned signer configuration may add
`"repositories": ["compoundingtech/factory", "schickling/ptg"]`.
The isolated signer independently validates the requested identity and checks
this exact allowlist before signing. A configured list rejects missing or
unlisted identities; an empty list denies all requests. Omission retains the
existing unrestricted signer behavior. This policy authorizes a claimed logical
identity, not the authenticity of an origin URL: only the verifier's independently
chosen expected identity prevents cross-repository evidence reuse.

`mergemaster evidence verify --repository OWNER/NAME ...` requires an exact
signed match, rejecting both missing and different identities. Stage policy
(`evidence-policy.json`, read from accepted BASE) may set `"repository"` to impose
the same requirement on every review and cited test. A CLI expectation cannot
override a conflicting policy identity. Without an expectation, verification
continues to accept existing unbound records as well as bound records.

This is an additive v1 extension: the predicate URI, observation schema version,
request/config versions and subject commit/tree semantics are unchanged.
When no identity is supplied, the new field is omitted, preserving old statement
bytes and old producer behavior. Updated readers accept historical statements
and configs without the field. Older strict readers reject newly bound records,
so upgrade verifiers before enabling producers and signer allowlists, then require
the expected identity in the consuming verifier/policy. Existing factory/ptg
lanes need not migrate simultaneously. The legacy verifier independently decodes
the same signed envelope and permits extra top-level fields; it does not enforce
this new identity. Its existing `--repository` argument only expands policy
placeholders and is not an expected signed identity. Legacy consumers must use
the modern `evidence verify --repository` check when adopting repository binding.

There is no default signer, `st sekrets` call or mandatory `flake.lock`.
`--signer` is a JSON argv array, never shell source. `--config` is explicit:
provision it outside the consumer repository as an account-owned regular file
with mode 0600. Its schema is:

```json
{
  "version": 1,
  "signer": "agent/operator",
  "ssh_key": "/absolute/private/key",
  "toolchain": {
    "runtime": "/absolute/runtime/artifact",
    "dependencies": {
      "external-library": "/absolute/dependency/artifact"
    }
  }
}
```

Each measurement path corresponds to the same named artifact in the committed
`environment.json`. A `sha256:` identity measures a file's complete bytes; a
`git:` identity requires a checkout at that exact commit with no dirty,
untracked or ignored files. The signing host platform must be a declared system key; the toolchain for that key binds execution.
Setup must actually use these artifacts and include the full dependency closure.
The wrapper and signer measure them independently; neither executes a consumer
setup script with signing authority.
Workspace cleanliness hashes actual tracked filesystem bytes against committed
blobs, independently of Git's stat cache and clean filters. Index entries marked
`skip-worktree` or `assume-unchanged` are refused, even if their bytes match.
The wrapper and signer share this check; it also applies to Git dependencies.

BASE lanes may declare materialized workspace `inputs` and writable `scratch`:

```json
"inputs": {
  "node_modules": {"name": "locked modules", "identity": "tree-sha256-v2:<64 lowercase hex>"},
  "repos/dependency": {"name": "dependency tree", "identity": "tree-sha256-v2:<64 lowercase hex>"}
},
"scratch": [".build"]
```

These are lane fields in `lanes.json`, not operator configuration. Provision inputs
before wrapping; the wrapper does not download or install them. In this consumer
shape, both dependency trees are measured inputs; only `.build` is writable scratch.
Do not classify dependencies as scratch to bypass measurement.

`sha256:` binds a regular file's bytes. The legacy `tree-sha256:` identity is
unchanged: it requires a physical directory root and refuses all symlinks and
special entries, preserving its exact v1 digest and refusal behavior. Its digest
is SHA-256 of compact JSON `[1, rows]`, with rows `[relative_path, kind, digest]`
sorted by UTF-8 path bytes. The root row has path `""`; kinds are `directory`,
`file`, or `executable` (any execute bit). Directory digests are `""`; file
digests are lowercase SHA-256. Empty directories are included.

Opt in to `tree-sha256-v2:` for measured symlink inputs. It hashes compact JSON
`[2, rows]`, retaining the same sorted row format, regular-file modes and empty
directories, and adds kind `symlink`. A symlink row's digest is lowercase SHA-256
of its raw target bytes, not its destination's bytes. Descendant symlinks are
recorded but not traversed; their canonical destinations must lie within the
same or another declared measured tree input, name a tracked file or a directory
prefix of tracked files in the verified-clean checkout, or lie within a registered
closure root of a BASE environment `nix:` artifact independently remeasured by
the observer. Tracked sibling package links are safe because both wrapper and
signer already check their actual tracked bytes against committed blobs.
Ignored/untracked destinations, scratch, Git metadata and checkout escapes are
not authorized by the tracked-path rule. Dangling links, cycles and special
entries remain refused.

The declared v2 tree root itself may be an absolute- or relative-target symlink
to a directory. Its raw target is hashed as the `symlink` row at path `""`, and
the resolved directory's full contents are measured under that root. There is
no additional directory row at `""`. Thus both root retargeting and changes to
the resolved tree affect the identity; a root link is not merely a target-string
measurement.

Each v2 observation records the validated graph's directory entries, entry kinds
and raw link targets, plus the kind and Unix device/inode identity of every
physical directory lookup component. Hashing follows that recorded graph,
rereads digest-row link targets, and refuses changes before completing the
observation, including ancestor directory substitutions, intermediate bridge links
and cached dependency cycles. V2 observation is explicitly refused on non-Unix
platforms, where this directory-identity binding is unavailable.
Standalone `tree_digest_v2` callers must independently measure every supplied
authority root; merely supplying a root does not measure its contents.
The original requested root lookup is also bound, including ancestor aliases and
their link chains, rather than only its canonical endpoint. Leaf files bind
content and the executable bit by path; transient changes restored between
checks (ABA) are not detected.

There is no blanket Nix-store exemption. Only the independently remeasured
closures of the current system's BASE environment runtime and dependencies
authorize Nix destinations; a caller-supplied closure receipt cannot authorize
links, and an unrelated `/nix/store` path is refused. The wrapper and signer
remeasure these closures at each workspace observation and require their claims
to match the initial wrapper inputs or signing request.
`.devenv/profile` must still be declared as a measured input (or be within one,
such as `.devenv`); a linked input root binds its raw target and resolved contents
as described above. Declaring `.devenv` does not implicitly authorize arbitrary
external trees. Mutable runtime links such as `.devenv/run` into `/tmp` remain
refused unless their destinations are separately declared measured trees.
Putting `.devenv` in scratch does not authorize any symlinks.

Roots must be literal repository-relative paths without trailing slashes. They
cannot overlap each other, tracked files (including ancestors), or Git metadata.
Canonical measured roots also cannot physically overlap each other, encompass
the repository, or alias tracked paths or scratch.
Root ancestors cannot be symlinks. Scratch must start absent or empty; the wrapper
creates it before execution. Only scratch may acquire output; its descendants
must remain regular files/directories. Every other ignored or untracked entry,
including empty directories, is refused. Inputs are measured before and after
execution and independently by the signer before and after signing. These are
cooperative byte checks, not an OS sandbox or protection from transient writes
restored before measurement.

Declarations bind signed inputs as `workspace_binding: "v2"` and
`workspace_declaration_sha256`: SHA-256 of compact JSON `[2, inputs, scratch]`
(input keys byte-sorted, artifact field order `name,identity`, scratch order
preserved). The object-only verifier recomputes this digest from BASE policy;
it never requires materializations in its checkout. With both declarations
absent or empty, Lane serialization and expected inputs remain unchanged, so
v0.1 evidence stays verifiable.

The new tree identity does not change the workspace-binding v2 declaration
format or object-only verification of existing v2 evidence.

The signing key must also be account-owned, mode 0600 and outside the consumer
checkout. An optional `path` field supplies a trusted executable search path;
otherwise the signer searches fixed system directories, not the caller's PATH.
Resolved Git/OpenSSH programs and their directories must be root-owned and
closed to other writers, or immutable Nix store paths. Loader/interpreter code
injection variables are refused. Git signing runs in an isolated scratch
repository with a closed environment, never the consumer's Git configuration.
The signer independently reads the requested commit, BASE policy and environment
digests, and owns the observation time and producer digest.

A dirty checkout (including undeclared ignored files), moved HEAD, changed input,
toolchain drift, signing failure or publication failure is non-success.

Nix artifacts use `nix:/nix/store/<32-character-store-hash>-<name>` (a literal
registered output root, not an expression or a subpath). The account configuration
must provision that exact path and include a trusted `nix` in its tool search
path. Both wrapper (before and after execution) and isolated signer independently
run `nix path-info --recursive --json`, refusing absent/invalid roots or members.
The signed input `nix_closure_sha256:<artifact-identity>` is SHA-256 of compact
JSON `[path,narHash]` tuples sorted by path, with SHA-256 NAR hashes. Closure
differences refuse signing. Existing SHA-256/Git artifact records remain valid;
the object-only gate does not invoke Nix or provision artifacts.
The `narHash` values come from Nix's registered metadata, trusting the Nix store;
they are not freshly recomputed NAR byte hashes by the workspace walker. Every
closure member, including members not reached by workspace links, must still
exist at the end of each workspace observation: GC that removes a member before
that final presence check causes refusal. Observations do not hold GC roots or
guarantee member availability after the check completes.

Non-derivation lanes preserve PATH-based wrapping for bare commands and checkout-relative
execution for relative commands by default. Set `"direct_exec": true` on a BASE lane to opt
into direct execution; it defaults to false and is omitted when false. Eligibility is exactly
`argv: ["bun", "<tracked-relative-script>"]`, with a `.ts`, `.tsx`, `.js`, `.mjs`, or `.cjs`
script: no extra arguments, leading flag, absolute script path, or `..` path segment.
The wrapper selects only the declared Nix runtime's `bin/bun`, never a dependency executable
or PATH substitute, canonicalizes it, checks runtime-closure membership, and executes that
canonical path. An ineligible opt-in is refused.

Absolute Nix executable lanes remain canonicalized and bound to a measured closure.
Both these lanes and `direct_exec` lanes require signed inputs `executed_executable`
(the canonical absolute executable path) and `executed_artifact` (the declared Nix artifact
identity whose measured closure contains it); for `direct_exec`, that artifact must be the
runtime. The signer independently checks both claims, and the gate requires them.
Before/after closure remeasurement is unchanged. Scripts, environment variables, subprocess
selection and transitive runtime behavior remain the cooperative lane author's responsibility:
this is measured evidence, not a sandbox.

### Nix flake-check lanes

Marker outputs are not executable runtime identities. A lane may instead declare
`"nix_check": {"attribute": "checks.x86_64-linux.example", "required": "fresh"}`
and `argv: ["/nix/store/<hash>-nix/bin/nix"]`. `required` defaults to `fresh`;
`any` explicitly permits reuse. The executable's output root must itself be a
`nix:` artifact in `environment.json`, provisioned at that exact store path on
every signing host. Invoke `evidence wrap` without a trailing command; `--reuse`
requests a realization without claiming fresh execution.

Wrapper and signer independently evaluate the attribute from the exact committed
HEAD using pure, Git-pinned flake evaluation, with import-from-derivation and lock
updates disabled. Only static-output derivations are supported. The signed
`nix_derivation` is the `.drv` store path: its hash covers build input derivations
and sources, unlike a marker's runtime closure. `nix_outputs_sha256` hashes sorted
compact JSON `[output_name, realized_path, narHash]` tuples.

Both processes use an isolated temporary HOME/XDG configuration directory,
`NIX_USER_CONF_FILES=/dev/null`, and controlled NIX_CONFIG plus explicit CLI
settings. Flake configuration acceptance is disabled, pure evaluation enabled,
and IFD disabled; candidate preferences and saved trusted settings cannot
override those restrictions. `nix config show --json` independently verifies
the effective settings. Execution pins `builders=""`, `build-hook=""` and
`max-jobs=1`: remote dispatch cannot silently turn a check-mode rebuild into
a normal remote realization. The store must be local, or `nix store info --json`
must identify a **trusted daemon client**, so restricted overrides take effect.
Untrusted daemon clients and any "ignoring the client-specified setting"
diagnostic fail closed. A usable local builder is required; none is silently
replaced by a remote builder. `nix_settings_sha256` binds the ordered setting
pairs (accept-flake-config=false, pure-eval=true,
allow-import-from-derivation=false, builders="", build-hook="", max-jobs=1);
`nix_store` and `nix_daemon_trusted` bind the observed store/trust boundary.

Fresh execution first realizes missing outputs, then **always** runs
`nix build --rebuild --option substitute false <drv>^*`. Only that final execution
is evidence, including when another client races or coalesces initial realization.
Cold outputs can therefore build twice. Fresh lanes must have deterministic
outputs: differing rebuild outputs fail the lane. `nix_execution` is `rebuild`
(fresh), `reused` (cached/substituted/otherwise realized; never claimed fresh), or
`failed` (no output or freshness assertion). `nix_command_mode` records the actual
command's rebuild/reused shape, including when cold preparation fails.
Failed cold builds and failed reused realizations are captured, signed and
published with their nonzero status, without `nix_outputs_sha256`.
The gate refuses reuse for `fresh`; `any` reports `execution_reused` with outcome
`reused`, not a fresh-test outcome.

The signed check command is the complete normalized argv actually executed,
including the trusted executable, fixed evaluation/build flags, `.drv` path and
execution flags, not an inert `nix build .#attribute` declaration.
`nix_command_sha256` binds those argv bytes as compact JSON. The signer recomputes
the argv from its independent evaluation; the read-only gate recomputes its shape
from BASE plus signed derivation/mode without running Nix. The lane-definition
digest continues binding the complete BASE attribute and freshness policy.

A failing lane is still signed and published, then exits nonzero. Complete
combined output is retained as a Git blob under
`refs/evidence-output/<output-sha256>` in the local checkout; its SHA-256 is
bound by the unchanged signed check format. The signature is a cooperative
wrapper attestation, not hardware isolation from an operator able to invoke the
signer. Existing Python evidence verification can read the same note, but
consumer policies that require legacy `flake_lock_sha256` must not be applied
to a generic environment lane.

Generic gate satisfaction accepts the pinned Python verifier's runner kinds:
`wrapper`, `nix`, `sekrets`, and any `github:`-prefixed observer runner.
A caller-supplied runner outside those kinds remains a valid evidence record
for inspection and native policy verification, but cannot satisfy the generic
gate (`unsupported_kind`). Re-attestation also preserves the exact subject
commit name and its verified/absent inspection binding, not only its tree.

PR and queue inspect the newest valid pass, passing over globally unaccepted
signer levels and otherwise-valid passes with the wrong lane-definition digest.
Other invalid passes decide; failures at or after pass minus 120 seconds veto
a valid pass. With no surviving pass, newest-trusted/failure-biased selection
applies. Push is unchanged; queue remains report-only.
Unsigned degraded records do not shadow trusted non-push candidates. A pass
with both a wrong lane digest and wrong bound input is conservatively refused
by Rust where Python can pass it over (recorded as P3 in `scripts/PROVENANCE`).

### Read-only informational reporter

`genie/generic-evidence.ts` exports `genericEvidenceReporterJob({ check, checkout,
runner? })` for `pull_request` workflows. The checkout action must be SHA-pinned;
the fragment checks out the event's accepted BASE, never the candidate worktree.
It downloads the verifier release declared by BASE's tool pin, verifies its
digest and source/workflow attestation, and fetches HEAD and evidence refs as
Git objects only. It never installs candidate dependencies, runs candidate
commands or setup, signs evidence, or writes statuses, checks or comments.
Ignored `node_modules`-style inputs and scratch files are not executed or
interpreted by this object-only reporter.

The job requests only `contents: read` and `pull-requests: read` and sets
`continue-on-error: true`. The latter permission is required to recheck the live
pull request in private repositories. Mocked API tests do not prove GitHub token
authorization; the generated-workflow golden asserts both declared read scopes.
Its only report surfaces are its step conclusion and an escaped job summary;
it must **not** be configured as a required check. Missing, refused or unavailable
evidence is informational failure, never authorization to skip a required lane.
A policy-accepted `skip/reused` decision is informational success, preserving the
gate's reuse summary without asserting fresh execution; `skip/satisfied` also succeeds.
Unlike the required publisher, it does not gather hosted review/check evidence
or accept a GitHub App token. Consumers retain their independent validation job
and required-check policy. See `tests/fixtures/generic-evidence/` for composition.

When a required BASE config blob (`tool-pin.json`, `lanes.json`,
`environment.json` or `evidence-keys`) is absent, the gate emits
`decision: "refuse"`, `outcome: "rejected"`, `reason: "config_missing"` with the
missing path in its summary. Candidate config never fills the gap. Invalid JSON,
symlinks, directories and Git/object failures remain errors without a decision,
not `config_missing`. A missing tool pin also prevents the workflow bootstrap
from acquiring a verifier; that bootstrap failure is reported as incomplete.
Required configuration is validated before expanding lane paths. Each load
lists the BASE tree once for all lanes; candidate manifests batch blob reads and
reuse content digests for overlapping inputs. An exact-tree record miss still
validates candidate input paths and objects, but does not hash their contents.
Both blob-read and object-check batches reject unterminated Git response headers.


## Base-only generic required-check publisher

`genie/generic-evidence.ts` exports `genericEvidenceRequiredJob`. Compose it
under `pull_request_target`; the function additionally enforces that event at
job runtime. The complete generator example and semantic YAML golden are in
`tests/fixtures/generic-evidence/`. Its separate `pull_request` validate job
has read-only permissions, no secrets, and an exact-head checkout. A trusted
label event reevaluates evidence after hosted validation or review completes.

The publisher checks out BASE only, downloads the x86_64 musl release named
by BASE's pin, checks the pinned SHA-256, and runs `gh attestation verify`
with the pinned source/workflow digest, release workflow identity, and
`--deny-self-hosted-runners`. HEAD and evidence refs are fetched as Git objects;
candidate source, setup, package installs, and signing never execute there.
Missing binary, provenance, evidence, token, or gate output fails closed.

The authenticated collection uses these GitHub REST endpoints:

```text
GET /repos/{repository}/pulls/{number}
GET /repos/{repository}/git/ref/heads/{encoded-base-ref}
GET /repos/{repository}/pulls/{number}/reviews?per_page=100&page=N
GET /repos/{repository}/commits/{head}/check-runs?filter=all&per_page=100&page=N
GET /repos/{repository}/actions/runs/{run_id}
GET /repos/{repository}/actions/runs/{run_id}/jobs?filter=latest&per_page=100&page=N
```

Reviews, checks and jobs are fully paginated. Check/run/job identity is joined
against authenticated Actions metadata, including the actual workflow path and
ID, not a PR-supplied label or URL alone. Only latest-attempt jobs qualify.
After the gate's live recheck, publication rechecks unchanged open PR HEAD and
accepted base once more before `POST /repos/{repository}/check-runs` at HEAD.
The gate's approval evaluation itself is offline; live authority rechecks
remain authenticated API operations outside that evaluator.

`appTokenStep` is the explicit integration point for a dedicated GitHub App
token-producing step (ID `app-token`, output `token`). Until configured, its
default placeholder exits unsuccessfully and cannot publish success. The
workflow token is read-only and never substitutes for the App token. App
creation, key provisioning, and consumer ruleset enrollment are separate from
this fragment; no App or ruleset is created by this PR.

## Release binaries and retained Graph-shaped proof

Version 0.3.0 adds explicit push-mode reuse of exact signed trees and permits
pull-request merges from accepted BASE ancestry. Push lanes require explicit
event opt-in; `foreign_merge` rejects unrelated merge parents, while push
refusals distinguish mismatched trees, disallowed events, non-default branches,
stale pushes and missing/wrong parent BASE. See [CHANGELOG.md](CHANGELOG.md) for
release notes and the contracts above for bootstrap and trust requirements.

`.github/workflows/release.yml` builds native Linux x86_64 and aarch64 musl
executables on GitHub-hosted runners. A pushed `vX.Y.Z` tag publishes
`mergemaster-x86_64-unknown-linux-musl`,
`mergemaster-aarch64-unknown-linux-musl`, and `SHA256SUMS`, with GitHub
build-provenance attestations for all three assets. Builds use locked Cargo
dependencies and reject an ELF interpreter or dynamic shared-library dependency.
Release setup uses rustup's self-contained musl CRT and a flake-lock-pinned
native musl C compiler/binutils wrapper from `packages.release-musl-toolchain`
for both native dependencies and the final link, without Ubuntu apt mirrors.
The runner image must already provide readelf.
Git and OpenSSH remain runtime prerequisites for evidence operations.
Before building a pushed tag, the workflow requires `vX.Y.Z` to match the
`package.version` in `crates/mergemaster-evidence/Cargo.toml` exactly.

Pull requests and `workflow_dispatch` build both architectures and assemble
checksums but cannot attest or publish, even when dispatch targets a tag.
No release exists until a maintainer pushes a version tag. Consumers must pin
the exact published asset digest and source revision; a version label alone
is not a trust boundary.

CI also runs `tests/test-graph-proof.py` with the built binary. This is an
independent Graph-shaped fixture, not a modification to a production Graph
repository. `tools/graph setup` resolves Vitest into a separate, committed Git
dependency closure. The committed environment binds the exact Node executable
and that full closure; `tools/graph check --full` runs the complete real Vitest
suite. The wrapper signs and publishes the observation to a fixture origin,
then the gate must return `skip/satisfied` for the exact candidate.
The `graph-full-check-proof` Actions artifact retains the post-setup repository
and dependency worktrees, complete Vitest output, setup output, and gate JSON.
It explicitly excludes the ephemeral private signing key and signer config.
Worktrees are archived as a tarball so Git file modes and dependency symlinks
survive download; the archive excludes signing secrets even on a failed proof.

To reproduce while keeping the proof directory:

```sh
package="$(nix build .# --no-link --print-out-paths)"
nix develop -c python3 tests/test-graph-proof.py \
  --binary "$package/bin/mergemaster" --work-dir /absolute/new/proof-directory
```

## Shared evidence-publisher infrastructure

`iac/stack.ts` declares one private, schickling-owned `Mergemaster Evidence`
GitHub App. `iac/consumers.json` is the shared enrollment allowlist consumed by
the stack and the central reconciler: each entry records a stable consumer ID,
owner, repository, numeric GitHub repository ID and default branch. Initial
consumers are `schickling/factory` (`graph`) and `schickling/ptg` (`ptg`).
Repository names alone are not enrollment identity.

The App requests `checks: write`, `contents: read` and `pull_requests: read`
(GitHub adds `metadata: read`), with no events. There is one shared App
registration and owner approval, not a registration per consumer. Selected-repo
installation consent is a separate necessary step: one installation on the
schickling account can select both enrolled repositories. Adding another
repository requires enrollment and installation consent, not another App
registration. Registration and installation are not one API action.
Organization consumers would require a public App registration and their own
installation consent.

The provider seals the private key **only** into
`compoundingtech/mergemaster`'s `mergemaster-check-publisher` environment as
`MERGEMASTER_APP_PRIVATE_KEY`. That environment permits only the exact `main`
branch. The stack creates no consumer environments, and consumers receive
neither the App key nor an installation token. No private key or callback code
enters resource props, outputs or state. The single-sink provider cannot fan
out the private key, by design.

The central GitHub-hosted reconciler in `compoundingtech/mergemaster` polls
enrolled repositories every five minutes; `workflow_dispatch` provides manual
repair. It reads and verifies evidence before publishing checks on the
corresponding PR head. Its installation tokens are scoped to one enrolled
repository with only the App permissions above. Consumer PR jobs do not run
privileged publication or choose arbitrary installations, repositories or
heads for a token broker. Local evidence signing and signer trust are
unchanged: the App publishes verified results; it does not sign local evidence.

### Offline infrastructure checks

The isolated package uses pnpm 12.17.0 and the pinned effect-utils provider:

```sh
mr apply --worktree-mode commit --only effect-utils
cd iac
pnpm install --frozen-lockfile --ignore-scripts
pnpm test
```

The plan test runs the real Alchemy planner with offline providers that reject
mutation. It asserts one App, only the central exact-main key environment,
the requested permissions and the non-secret enrollment outputs. The manifest
conversion regression uses only a loopback HTTP fixture and proves a single
private-key sink write, no callback code in state, and secret-free outputs.
These tests do not change a live App, installation, environment, secret,
ruleset or check run.

### Registration, installation and runtime configuration

The shared App has not been registered. No deploy or live mutation was run for
this change; source declarations and offline fixtures are not evidence of a live
registration, installation or working reconciler.

Use the protected operator state with `pnpm run plan` / `pnpm run deploy`
only during an approved deployment. `MERGEMASTER_IAC_STATE_DIR` must name an
absolute, external directory, with 0700 directories and 0600 files. The operator
wrappers check state before and after execution; `pnpm run check-state`
also checks it explicitly. Registered App deletion fails closed.

For registration, pending output provides `publisher.manifestHtml`,
`publisher.state` and `publisher.expiresAt`. Submit the manifest for the shared
owner approval. Pass its returned one-use callback code through
`APP_MANIFEST_CODE`, with the matching pending state in
`APP_MANIFEST_CODE_STATE`, for the conversion deploy.
`ManifestCodes.fromEnv('APP_MANIFEST_CODE')` keeps the code out of durable
inputs. There are no per-consumer registration inputs. The code and private key
are secret; never put them in arguments, logs, chat or git.

After registration, `publisher.integrationId` and `publisher.slug` are public
outputs. Follow `installation.url` and grant installation access to **only**
the selected repositories listed in `installation.repositories`. The output
reports `consent-required`, not an assertion that installation has occurred.
`consumers.<id>` exposes only owner, repository, numeric repository ID and
default branch, matching the enrollment allowlist. App IDs and installation
IDs are different identifiers.

Set the **public repository Actions variable** `MERGEMASTER_APP_ID` in
`compoundingtech/mergemaster` to the registered `publisher.integrationId`.
The central workflow reads that variable and the environment-scoped
`MERGEMASTER_APP_PRIVATE_KEY` secret; do not put the private key in a variable
or copy it to consumers. Installation consent and runtime configuration must
be complete before enabling central publication.

Consumer required-check contexts remain their BASE `required_evidence` lane
IDs. After installation and successful central publication, bind every required
lane context to the same `integration_id = publisher.integrationId`; do not
substitute consumer IDs, lane display names or installation IDs. App binding
rejects checks from other Apps, not forged checks from someone holding this
same App's key or a checks-write installation token. A leaked scoped token
lasts at most one hour; a leaked App private key can mint tokens for every
installation regardless of the originally requested token scope.

### Scheduled verification and repair

`.github/workflows/evidence-reconcile.yml` builds the `evidence-reconciler` flake
package and runs `mergemaster-reconciler` on a GitHub-hosted Ubuntu runner every
five minutes (`2-57/5 * * * *`) and accepts
manual `workflow_dispatch`. Both paths are restricted to `main`, use the central
`mergemaster-check-publisher` environment and share one concurrency group.
No fleet host, webhook receiver, consumer dispatch credential or consumer App
secret is required. Scheduling is best effort: GitHub can delay or drop a run;
the next successful sweep revisits current open PRs and durable evidence.

The runtime is a separate Rust binary crate, `crates/mergemaster-reconciler`.
Polling, GitHub credentials and publication stay outside the evidence verifier's
CLI/trust core: the reconciler still invokes the independently BASE-pinned
verifier release. It reuses the workspace's `jsonwebtoken`/AWS-LC RS256 and serde
dependency graph, and the existing trusted `gh` HTTP transport convention for
API and provenance calls. No new HTTP library or crypto implementation is added.
The flake package supplies its Git/SSH/GPG/GitHub CLI runtime tools; `scripts/`
remains the unchanged parity-oracle surface. Local signing keys never enter
Actions.
The restricted child `PATH` includes independently resolved Git, GitHub CLI and
`ssh-keygen` directories, so the pinned verifier can validate SSH-signed evidence
without searching the BASE checkout or caller-controlled paths. The reconciler
flake check exercises this production subprocess adapter against a real
ephemeral SSH-signed Git commit using the package wrapper's runtime tool set.

`iac/consumers.json` is the reconciler's sole enrollment allowlist, compiled into
the binary. Unknown dispatch repositories are rejected. For each enrolled
numeric repository ID, the reconciler discovers that App's installation and
requires `repository_selection: selected`; an all-repositories installation
fails closed before token minting. It mints a token with exactly one enrolled
`repository_ids` entry and `checks: write`, `contents: read`, `pull_requests: read`.
Both the token response and its paginated installation repository listing must
expose exactly that enrolled repository; unexpected IDs or names fail closed
before verification or publication. Live repository/account identity is also
checked before using the token.

This does not prove that the installation contains no other selected repository:
GitHub's installation repository listing reflects the token's narrowed scope.
An extra selected repository outside that scope is not detectable with the
App JWT and these least-privilege tokens. Detecting it would require broader
credentials; the reconciler deliberately does not mint an unscoped token.
Enrollment remains the authority for every token and publication target.

For each same-repository open PR, it observes the live target branch, reads
the required lane list and verifier pin from that accepted BASE, fetches HEAD
and evidence refs as data, and checks out **only BASE**. The BASE-pinned release
must match its SHA-256 and GitHub attestation source revision and release
workflow. That existing verifier reads the BASE-controlled policy and signer
keys and decides whether signed evidence authorizes each required lane.
Candidate source is never run and no fallback build is performed.

The synthesized verifier event contains authenticated PR/repository/base
observations, not dispatch-supplied conclusions. Central workflow actor metadata
is retained rather than inventing the original PR event actor. Fork PRs remain
unsupported, as with the existing generic publisher. Policies needing hosted
approval/check evidence fail closed: this reconciler does not collect hosted
evidence or request the unapproved `actions: read` App grant.

Immediately before publishing, the reconciler rechecks the live PR, HEAD and
accepted base. Success requires the verifier's exact lane/base/head identity,
`skip` with `satisfied` or `reused`, and a non-report-only successful process.
Missing or invalid verification is never success. Existing check runs matching
the lane name, HEAD and shared App are updated with `PATCH`; only a missing run
is created. Historical matching duplicates are repaired together. This is
serialized single-workflow reconciliation, not a claim that GitHub provides an
atomic external-ID uniqueness constraint for arbitrary concurrent publishers.

After registration, installation and runtime configuration, an authorized
operator can request an immediate current-state repair:

```sh
gh workflow run evidence-reconcile.yml --repo compoundingtech/mergemaster \
  --ref main -f repo=schickling/factory -f pr=123
```

Omit either filter to expand within the enrollment allowlist; omitting both
reconciles every enrolled repository's open PRs. Unknown repository names and
nonpositive PR numbers fail closed. A re-run/backfill recomputes current
HEAD/BASE and evidence; it never replays an old caller's success claim.
Local signing continues independently during publisher outages, and signed
notes remain in the consumer's origin until a subsequent sweep can verify them.

Offline runtime tests use reduced recorded API identity fixtures and synthetic
credential/check responses; no live writes or recorded secrets are involved:

```sh
nix build .#evidence-reconciler
nix build .#checks.x86_64-linux.evidence-reconciler
```

The same suite is wired into CI and `nix flake check`. It covers enrollment and
token scoping, BASE-only authorization reads, release provenance, exact verifier
identity, stale HEAD/base refusal, existing-check updates and workflow key
isolation.

Consumers retain their unprivileged validation and optional informational
reporters; central publication needs no consumer App environment or key.
The legacy `genericEvidenceRequiredJob` adapter is not used by this reconciler.
Retiring that adapter and updating any separately pinned consumer-generated
workflows is a separate consumer rollout; do not configure its old privileged
job as a required check or provision a consumer key for this central setup.
