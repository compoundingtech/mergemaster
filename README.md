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

Rust signer/verifier parity tests read the immutable v0.5.0 Python source pinned
by the `python-oracle` flake input, not the working-tree scripts.
`MERGEMASTER_PYTHON_ORACLE` names that source root and is required for those tests;
the dev shell and `checks.evidence` set it automatically. The production package
does not depend on the oracle or run its parity tests.

`checks.oracle-scripts` compares every remaining working-tree script's bytes and
executable bits with the pinned oracle. Deletions are allowed; additions or edits
fail. The explicit exemptions are repository-owned `PROVENANCE`, `test-scripts`,
`parity-drift`, and `parity-drift-test`, rather than copied upstream scripts.

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
The native command requires Git and OpenSSH, not Python. `scripts/evidence-keygen`
remains unchanged for existing script consumers and as an independent parity oracle;
it does not require an installed native binary.

The focused parity check loads `scripts/evidence-keygen` and every assertion in
`scripts/evidence-keygen-test` from `MERGEMASTER_PYTHON_ORACLE`, not the working tree,
and tests both implementations plus cross-implementation reuse and refusal cases:
`nix develop -c cargo test -p mergemaster-evidence --test keygen` (non-root).

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
# Or, with dependencies and all three pinned-source environment variables set:
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
and assertions from `MERGEMASTER_PYTHON_ORACLE` against real local Git histories.
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
import { readFileSync } from 'node:fs'

const actions = {
  checkout: 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1', // v7.0.1
  uploadArtifact: 'actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9', // v7.0.2
  downloadArtifact: 'actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333', // v8.0.2
}
const jobs = {
  ...evidenceGateJobs({ checks: ['linux-gate'], actions }),
  'evidence-source': evidenceSourceJob(
    readFileSync(new URL('./repos/mergemaster/scripts/ci-evidence-source', import.meta.url), 'utf8'),
    actions,
  ),
}
```

Source retention embeds the real `scripts/ci-evidence-source` producer when
generating YAML, never a separately maintained copy. Signing fragments take
the consumer's full-history checkout steps, signing environment, check names,
and lane-specific web-note environment. `configDir` and `legacyConfigDir`
default to `.fractal` and `.st`; the accepted base decides which key file exists.
Script command names and record formats remain unchanged.

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
settings through the same real pinned effect-utils generator, requiring
byte-identical output. It also compares every fleet evidence job and the
complete observer and signed-tree workflows against the committed fixture
YAML. The shell supplies `oxfmt`, which genie invokes after serialization;
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
  "system": "x86_64-linux",
  "toolchain": {
    "runtime": {"name": "bun", "identity": "sha256:<64-hex-runtime-artifact-digest>"},
    "dependencies": {
      "external-library": {"name": "external-library", "identity": "git:<40-hex-commit>"}
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
Event helpers retain signer-level event order when narrowing check permissions
and identify shard parts only from the configured producer kind and index input.
Routing requires a signature-verified principal and a validated generic check.
The runner-prefix guard follows any required lazy lane lookup, before age/input
judgments; routing alone never authorizes a record.
The legacy clock/input guard takes an explicit clock and preserves future, age,
required-input, exit-code, command and value-check refusal order.
`legacy_verify::lanes::LaneRules` validates one selected accepted-base lane,
preserving optional-field truthiness without reading Git or authorizing evidence.
Legacy definition hashing streams Python-compatible Git-entry/argv bytes,
including surrogateescaped filenames; native lane hashing remains unchanged.
Legacy lane-entry parsing preserves integer lexemes and reports unsupported JSON explicitly.
Canonical lane-entry comparisons use Python-compatible sorted compact JSON text,
not parsed-value equality; callers compare before validating the lane schema.
`legacy_verify::judgment::judge` routes before lazy lane lookup, then checks the
runner, clock/inputs, lane identity and ordered Git bindings. Earlier guards
never fetch later provider resources; a supplied lane avoids the lazy lookup.
Legacy `lane_git::lane_definition` discovers definition/absent files in real Git
trees, preserving raw changed-path bytes and accepted-base existence checks.
`lane_git::lane_for` resolves accepted/branch-point lane files independently,
checks ancestry and compares canonical entries before accepted-lane validation.
Legacy `discovery::input_refs` and `with_note_for` find indexed candidates and
batch note-entry presence only; neither establishes statement or signer trust.
Lane discovery uses the gate's sanitized Git command and rejects malformed or
unterminated ls-tree rows; shared subprocess timeout/output bounds remain open.
`workflow::workflow_job` selects exact generated-workflow text and transitive
job dependencies; it follows the legacy layout contract, not general YAML.

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
untracked or ignored files. The measured system must equal the declared system.
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
  "node_modules": {"name": "locked modules", "identity": "tree-sha256:<64 lowercase hex>"}
},
"scratch": [".build"]
```

These are lane fields in `lanes.json`, not operator configuration. Provision inputs
before wrapping; the wrapper does not download or install them. `sha256:` binds a
regular file's bytes. `tree-sha256:` binds a directory: SHA-256 of compact JSON
`[1, rows]`, with rows `[relative_path, kind, digest]` sorted by UTF-8 path bytes.
The root row has path `""`; kinds are `directory`, `file`, or `executable` (any
execute bit). Directory digests are `""`; file digests are lowercase SHA-256.
Empty directories are included. Symlinks and special entries are refused.

Roots must be literal repository-relative paths without trailing slashes. They
cannot overlap each other, tracked files (including ancestors), or Git metadata.
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

For a non-derivation lane using any Nix artifact, BASE lane `argv[0]` must be absolute and resolve to an
executable inside a measured closure member. This is the required execution
binding, checked independently by wrapper and signer; a mutable PATH launcher
outside those closures is refused. Scripts, environment variables, subprocess
selection and transitive runtime behavior remain the cooperative lane author's
responsibility: this is measured evidence, not a sandbox. Put required runtimes
in the declared closure and do not use ambient PATH to substitute dependencies.

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

## Repository check-publisher infrastructure

`iac/alchemy.run.ts` owns one private, user-owned GitHub App per entry in
`iac/stack.ts`. The Graph entry targets `schickling/factory`, whose
default branch is `main`. Its App requests only `checks: write` (GitHub adds
`metadata: read`), has no events or active webhook, and has no author allowlist.
The Graph repository owns its ruleset and consumer workflows; this stack
does not declare a ruleset or run candidate code.

The environment `mergemaster-check-publisher` permits only the exact `main`
branch, not all protected branches. The App provider seals the private key
directly into that environment's `MERGEMASTER_APP_PRIVATE_KEY` Actions secret.
There is deliberately no separate `GitHub.Secret` resource: neither a PEM
input nor a PEM output belongs in Alchemy state. Deployment credentials need
repository administration/environment and Actions-secret access; these are
separate from the new App's checks-only runtime credential. Private-repository
environment support requires a compatible GitHub plan.

### Operator manifest registration

The isolated IaC package uses pnpm 12.15.0, the fleet pin from the composed
effect-utils `nix/pnpm.nix`, with its own `iac/pnpm-lock.yaml`.
Node 24.20.0 is used in hosted CI. The pinned effect-utils source is composed
through `megarepo.lock`; pnpm's `file:` dependency installs the unpublished
provider with its dependencies, rather than linking an uninstalled checkout.
The small Oxc loader uses Alchemy's own runtime tooling to load that
provider's TypeScript without building effect-utils.

```sh
mr apply --worktree-mode commit --only effect-utils
cd iac
pnpm install --frozen-lockfile --ignore-scripts
pnpm test                       # offline; no GitHub credentials or mutation
umask 077
pnpm run plan                   # review before deploying
pnpm run deploy                 # first deployment: pending manifest, not an App
```

Only an operator with delegated owner consent may continue. Submit the
`graph.manifestHtml` form from the pending output in the owner's authenticated
browser session. The form POST is required; navigating to its action URL alone
does not submit the manifest. The loopback redirect
`http://127.0.0.1:8787/github-app-callback` carries the one-time `code` and
`state`; a refused connection is harmless because those values remain in the
address bar. Compare state to `graph.state` and complete within one hour.
Read the code through a trusted secret-input path, not a literal shell command
or a committed env file; then, with `APP_MANIFEST_CODE` and
`APP_MANIFEST_CODE_STATE` exported in that same operator shell:

```sh
pnpm run deploy
unset APP_MANIFEST_CODE APP_MANIFEST_CODE_STATE
```

The apply-time `ManifestCodes.fromEnv('APP_MANIFEST_CODE')` source reads the
code and its companion `APP_MANIFEST_CODE_STATE` only during conversion;
planning and provider construction never read the code. Only
`conversion.state` enters resource inputs: that token is non-secret because
it is already a pending output and part of the manifest form. The provider
fix ends the callback-code-in-state exception: the code is never a resource
input, durable state value or stack output, so no purge deploy is required.
After successful registration, run `pnpm run check-state` before backup.

Install the App on **only** `schickling/factory`. Registered outputs
are `graph.status`, `graph.integrationId`, and `graph.slug`. Pending outputs
are `graph.status`, `graph.manifestHtml`, `graph.state`, and `graph.expiresAt`;
there is no integration ID until registration succeeds. Give
`graph.integrationId` (the App ID, not an installation ID) to the Graph
ruleset owner for the required `graph-full-check` integration binding.

The base-only publisher is `genericEvidenceRequiredJob` from
`genie/generic-evidence.ts`, running on `pull_request_target`; the independent
unprivileged `validate` workflow remains `.github/workflows/validate.yml`.
Its consumer must set job `environment: 'mergemaster-check-publisher'` and
supply `appTokenStep` using a SHA-pinned `actions/create-github-app-token`:
`app-id` is the exported integration ID, `private-key` is
`${{ secrets.MERGEMASTER_APP_PRIVATE_KEY }}`, `owner` is `schickling`, and
`repositories` is `factory`. The fragment assigns step ID `app-token`
and consumes its `token` output; it never falls back to `GITHUB_TOKEN`.
There were no pre-existing environment or secret names in the generic
fragment; the names above are this stack's explicit consumer contract.

### Interim: local operator state and operator apply

The interim exception covers **App bootstrap only**: local operator state and
operator-run deploy, because the manifest consent flow cannot run in CI.
When the Effect-utils Manager's program remote state backend lands (due
2026-11-12), this stack moves to that backend and to CI-applied plan plus
drift detection on `main`, no later than **2026-11-19**.

`MERGEMASTER_IAC_STATE_DIR` configures the absolute state root, defaulting to
`${XDG_STATE_HOME:-$HOME/.local/state}/mergemaster/iac`; Alchemy stores its
state under that root's `state/` subdirectory. The root must be outside the
repository checkout, including through symlink aliases. The supported
`AlchemyContext` directory injection is scoped to `localState()` only;
other runtime artifacts retain Alchemy's defaults. Local state is accepted
because it contains no private key and a registered App can be recovered
with adopt-by-slug if state is lost.

Use the documented `pnpm run plan` and `pnpm run deploy` commands: they set
umask 077 and check the state tree before and after the CLI exits. Directories
must be 0700, regular files 0600; symlinks and looser modes fail closed,
without silently changing existing permissions. After every deploy, run
`pnpm run check-state`: it must find **no** PEM/`-----BEGIN`/private-key value
markers, `conversion.code` properties or `__redacted__` values anywhere in the
state tree. Secret destination names such as `MERGEMASTER_APP_PRIVATE_KEY`
are non-secret metadata, not key values; the scanner permits those names
and never prints matched contents.

Take the state backup only after a successful registration (status registered
with an integrationId) and a clean state check; keep it protected until
migration. Legacy state containing callback codes must be cleaned without
printing them before strict checks permit plan/deploy or backup.

```sh
pnpm run check-state
state_dir="${MERGEMASTER_IAC_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/mergemaster/iac}"
backup_dir="${state_dir}.backup-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$backup_dir"
cp -a "$state_dir/." "$backup_dir/"
```

Retain the same state root across both manifest deployments. Lost pending
state cannot be recovered by adoption before an App exists. CI runs offline
tests only during the bootstrap exception. Do not create preview stages
for these long-lived Apps. Permission/event drift is a typed
hard error. Registered destruction fails closed: uninstall/delete in the
owner UI; the stack never automatically orphans an App or destroys its key.
After ambiguous conversion failure, do not replay the one-use code: inspect
the owner UI, revoke/rotate and reseed the same secret through a trusted
secret-management path, then use `APP_ADOPT_SLUG` with `pnpm run deploy` and
unset it afterward. `APP_REPOSITORY` selects the entry for conversion/adoption
(default `graph`); adding future repositories requires one table entry each.