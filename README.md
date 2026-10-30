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
  checkout: 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262', // v4
  uploadArtifact: 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02', // v4
  downloadArtifact: 'actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093', // v4
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
`max_age_seconds` bounds signed observation age. `authors.mode=none` adds no
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
whitespace. These hashes supplement exact signed commit and tree identity;
they never permit cross-tree evidence reuse.

`skip/satisfied` means trusted evidence covers the exact lane, not a skipped
required GitHub job. `refuse` must fail the required check; `run` must execute
the real fallback or fail. A computed decision exits zero even for refusal;
usage/internal failures exit nonzero and missing outputs are never success.
Use a read-only, base-owned `pull_request_target` bootstrap with no candidate
checkout execution or private signing keys. Publish the required check on the
explicit HEAD, recheck unchanged HEAD and accepted base before success, and
require strict up-to-date branch protection. Graph's required-evidence lane
does not run Graph in Actions. Authenticated release publication and consumer
setup enforcement remain prerequisites; copied Fractal wrappers retain their
original contracts and are not generic environment producers.

The JSON result contains `version`, `check`, `base`, `head`, `tree`, `decision`,
`outcome`, `reason`, `record` (an immutable record ID or null),
`protected_paths` (the touched protected paths, empty otherwise), and `summary`.
`protected_edits: "reject"` always refuses protected edits, even for
optional-fallback lanes. A BASE-authorized `human_approval` policy permits the
explicit review/hosted-check path described below; agent signatures alone
never authorize protected changes.
The stable reason codes are `satisfied`, `base_not_ancestor`, `merge_history`, `protected_paths`,
`ineligible_event`, `no_record`, `invalid_record`, `untrusted_signer`,
`wrong_check`, `stale_tree`, `degraded`, `untrusted_tier`, `wrong_commit`,
`untrusted_level`, `future_dated`, `too_old`, `check_failed`, `wrong_command`,
`wrong_input`, `workspace_dirty`, `approval_evidence_missing`, `human_approval_missing`,
`hosted_check_missing`, and `human_approval_satisfied`. Consumers branch on these codes, not
diagnostic prose. Malformed configuration or unavailable Git plumbing is an
error, not a computed satisfaction result.
Merge commits anywhere in `BASE..HEAD` refuse. Protected comparisons use
Unicode NFKC normalization and lowercase component matching, including ancestor
replacement paths; signatures cannot authorize replacing a protected root with
a symlink. Live head/base movement or unavailable live authority is an error,
with no decision output, rather than a transferable success.

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

The signing key must also be account-owned, mode 0600 and outside the consumer
checkout. An optional `path` field supplies a trusted executable search path;
otherwise the signer searches fixed system directories, not the caller's PATH.
Resolved Git/OpenSSH programs and their directories must be root-owned and
closed to other writers, or immutable Nix store paths. Loader/interpreter code
injection variables are refused. Git signing runs in an isolated scratch
repository with a closed environment, never the consumer's Git configuration.
The signer independently reads the requested commit, BASE policy and environment
digests, and owns the observation time and producer digest.

A dirty checkout (including ignored files), moved HEAD, changed input,
toolchain drift, signing failure or publication failure is non-success.
A failing lane is still signed and published, then exits nonzero. Complete
combined output is retained as a Git blob under
`refs/evidence-output/<output-sha256>` in the local checkout; its SHA-256 is
bound by the unchanged signed check format. The signature is a cooperative
wrapper attestation, not hardware isolation from an operator able to invoke the
signer. Existing Python evidence verification can read the same note, but
consumer policies that require legacy `flake_lock_sha256` must not be applied
to a generic environment lane.
## Release binaries and retained Graph-shaped proof

`.github/workflows/release.yml` builds native Linux x86_64 and aarch64 musl
executables on GitHub-hosted runners. A pushed `vX.Y.Z` tag publishes
`mergemaster-x86_64-unknown-linux-musl`,
`mergemaster-aarch64-unknown-linux-musl`, and `SHA256SUMS`, with GitHub
build-provenance attestations for all three assets. Builds use locked Cargo
dependencies and reject an ELF interpreter or dynamic shared-library dependency.
Git and OpenSSH remain runtime prerequisites for evidence operations.

Pull requests and `workflow_dispatch` build both architectures and assemble
checksums but cannot attest or publish, even when dispatch targets a tag.
No release exists until a maintainer pushes a version tag. Consumers must pin
the exact published asset digest and source revision; a version label alone
is not a trust boundary.

