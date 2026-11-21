# Selective evidence reuse across main moves (design)

Step: step-run/01a1fdddfc677920ab1659e38c430576/reuse-gate-core (mission dotfiles-queue).
Code references are to compoundingtech/mergemaster main c7a38431.

## 1. Problem

A batch train moves main for every merge. Each move gives each queued PR a new
merge HEAD and tree. Today the native gate accepts a note only for the exact
head commit and tree:

- `satisfy()` refuses `wrong_commit` when the subject is not the head, and
  `stale_tree` when the subject tree differs (gate.rs:1078-1091).
- README:588 gives the reason: pull-request mode needs exact signed commit and
  tree identity; push mode may transfer evidence only between identical trees.

So every main move reruns every check of every queued PR, even when nothing
the check reads has changed.

## 2. What a note binds today

| Input of the check | Where it is bound | Checked by the gate? |
|---|---|---|
| Source tree and flake lock (Nix lane) | inside the `.drv`: the producer evaluates `git+file://<repo>?rev=<head>#<attr>.drvPath` with pure eval, no IFD, no lock update, isolated HOME and `NIX_USER_CONF_FILES=/dev/null` (signing.rs:536, derivation.rs) | Indirectly: the gate re-derives argv from the signed drv path, and `stale_tree` binds the tree. The gate never evaluates Nix. |
| Nix settings, store and command | `nix_settings_sha256`, `nix_store`, `nix_daemon_trusted`, `nix_command_sha256`, `nix_command_mode`/`nix_execution` | Yes (gate.rs:1123-1157) |
| Lane definition (argv, definition paths) | `lane_definition_sha256` over `[1, check, lane, definition_files]` read at BASE | Yes, through expected_inputs (config.rs:809) |
| Environment and toolchain | `env_sha256`, `toolchain_sha256`, system | Yes, through expected_inputs |
| Workspace (non-Nix lanes) | declared inputs and scratch, plus `workspace_clean` and no untracked files | Declared subset only. It is not a closure of what the command reads. |
| Producer binary | `wrapper_sha256` = sha256 of the producer's own executable (generic.rs) | See §6. |
| Trust | signer principal `<level>/<name>`, tier, runner kind, repository | Yes: tier must be full; level in the lane's trust_levels; runner in nix, wrapper, sekrets or github:*; repository_refusal (gate.rs:1068-1100) |

## 3. Options

### A. Gate-side reuse (rejected)

The gate would evaluate the drv at the candidate head and accept an older note
with an equal drv. Rejected:

- The gate would run Nix evaluation of untrusted PR code inside the read-only
  gate job. That is a new attack and cost surface, and today the gate runs no
  Nix (README).
- It would weaken the exact-head rule in README:588 for every consumer.
- Non-Nix lanes have no closure key (§2), so they could not use it anyway.

### B. Producer-side re-attestation (proposed)

Keep the gate unchanged. Add a producer mode, `rebind`, that issues a new
exact-head note for a candidate by proving that the check's inputs are equal
to those of an existing verified note:

1. Input: the candidate HEAD+MAIN+tree (prepared by native landing or the
   train), the check and a prior evidence ID R.
2. R must be a root: a fresh execution (`nix_execution=rebuild`) with no
   `reused_from`. A reused note can never be the source of another rebind, so
   chains do not exist. Every rebind cites its root directly.
3. The producer verifies R with the same verifier the gate uses, under the
   candidate's BASE keys and policy: same lane, tier full, a signer level the
   lane trusts, check passed, same repository, and R's execution time within
   the lane's `max_age_seconds`. A root signed by a key that BASE no longer
   trusts fails here.
4. Admission of the lane and the build:
   - the lane's freshness requirement is `any`. Lanes that require `fresh`
     never qualify, and the gate already refuses reused evidence for them
     (gate.rs:1181-1189);
   - the check derivation is input-addressed: not fixed-output, not
     `__impure`, and without `__noChroot`. The producer checks this with
     `nix derivation show` on the drv;
   - the producer's effective Nix configuration has `sandbox = true`, no
     sandbox fallback, and no `impure-derivations` experimental feature. It
     records these values in a new signed claim, `nix_sandbox_sha256`. R must
     carry the same claim, so roots produced before this claim existed do not
     qualify.
5. The producer evaluates the drv at the candidate head the same way as a
   fresh run (signing.rs:536). Reuse is allowed only if all of these hold:
   - the drv path is byte-equal to R's `nix_derivation`;
   - `lane_definition_sha256`, `environment_sha256`, `toolchain_sha256`,
     system and the workspace declaration, computed with the shared
     `expected_inputs` (files at the candidate HEAD, declarations from BASE),
     equal R's;
   - `nix_settings_sha256` and `nix_sandbox_sha256` equal R's;
   - the producer's own `wrapper_sha256` and R's both equal the BASE tool
     pin;
   - the producer's signer level equals R's signer level (§5).
6. It realises the output (`nix build` of the same drv, without `--rebuild`).
   That substitutes the output or finds it in the store. It records
   `nix_execution=reused` and checks `nix_outputs_sha256` against R's. Store
   kind, daemon trust, closure claims and workspace flags are measured fresh
   for this observation, never copied from R. `attempt` describes this
   observation.
7. It signs a new statement for the candidate head and tree with the normal
   exact-head subject. `observed_at` is R's execution time, not the time of
   the rebind; the rebind time goes in `attested_at`. The statement also
   carries `reused_from: R` and `reuse_key` (the equal values from step 5).

The gate then sees an ordinary exact-head note and applies every existing
check. Because `observed_at` is the root's execution time, the gate's
existing `max_age_seconds` check bounds the whole reuse: a rebind can never
extend a result's lifetime. The decision names the reuse through
`reused_from`, as the step's acceptance requires ("reuses its verified
evidence ID").

Any mismatch gives a typed refusal, and the producer runs the check fresh:
`reuse_source_not_root`, `reuse_source_unverified`, `reuse_lane_requires_fresh`,
`reuse_impure_derivation`, `reuse_sandbox_changed`, `reuse_drv_changed`,
`reuse_lane_changed`, `reuse_environment_changed`, `reuse_tool_pin_changed`,
`reuse_trust_class_changed`.

Cost: one pure `nix eval`, one `nix derivation show` and a store lookup per
lane and candidate. That is seconds instead of the check's run time.

## 4. Coverage proof (Nix lanes)

Claim: when steps 2-6 pass, the check's result at the candidate equals the
root's result.

- The build is a function of the drv. The drv is a pure-eval function of the
  source at the head. Under `pure-eval`, file system and network access during
  evaluation are limited to inputs pinned by a cryptographic hash, and impure
  constants such as `builtins.currentSystem` and `builtins.currentTime` are
  disabled ([nix.conf: pure-eval](https://nix.dev/manual/nix/2.35/command-ref/conf-file.html)).
  Import-from-derivation is off, and the lock file is neither written nor
  updated (derivation.rs:11-18, :133-154). So every source file, flake input
  and lock entry the build can read is inside the drv hash.
- The build of an input-addressed derivation runs in the sandbox without
  network access. Only fixed-output derivations get network access, and their
  output is checked against a declared hash. Impure derivations are a separate
  output type ([Nix: derivation outputs](https://nix.dev/manual/nix/2.29/store/derivation/outputs/index.html)).
  Step 4 excludes fixed-output, impure and `__noChroot` check derivations and
  requires the sandbox, so the build sees only its declared inputs. Fixed-output
  dependencies, such as fetchers, are bound by their content hash.
- What runs is the lane argv applied to the drv (derivation::argv). The argv
  comes from the lane definition, bound by `lane_definition_sha256`.
- How it runs: Nix settings, sandbox settings, store kind and daemon trust are
  bound by their claims and checked again.
- What produced the claim: both producer binaries match the BASE tool pin.
- Who vouches: the same signer level, a full tier, and keys BASE still trusts
  for both the root and the rebind (§5).

The check's result depends only on the build. For a `nix_check` lane the
signed exit code is the status of `nix build` on the drv (derivation.rs:243-270,
generic.rs:259-281). Its output exists only if the build succeeded, and
`nix_outputs_sha256` binds that output. Identical output does not prove an
identical execution (logs, timing, host). That is why reuse records
`nix_execution=reused`, and why lanes that require a fresh execution never
qualify.

## 5. Trust classes and revocation

- A rebinding signer is never of a lower trust class than the root's signer.
  This design requires the same signer level, which is stricter. The gate then
  applies the lane's trust_levels to the rebinding signer as usual.
- A rebind never crosses repositories: the root's repository, the
  candidate's repository and the new note's repository must be equal, and the
  repository identity is required (not optional) for reuse.
- Tier must be full for the root. Degraded and test tiers never qualify.
- Runner kind must be `nix`. The wrapper, sekrets and github:* runners never
  qualify.
- Revocation: every rebind verifies the root under the candidate's BASE keys
  (step 3), and the gate verifies the rebinding signer under the same keys. If
  BASE stops trusting the root's key, no new rebind of that root is possible.
  A rebind note issued before the revocation stays valid only until the
  root's `max_age_seconds` runs out, because its `observed_at` is the root's
  execution time. If that window is too long for a revocation, the response
  is to revoke the rebinding key as well, or to lower the lane's
  `max_age_seconds`.


## 6. Prerequisite

Reuse depends on the producer digest binding (`wrapper_sha256` against the
BASE tool pin) in the gate. That lands as a separate change first.

## 7. Out of scope

- Non-Nix lanes: no closure key exists, so they keep exact-head evidence.
- Merge groups: they stay report-only (gate.rs:149-165).
- Push mode: unchanged (identical-tree transfer only).
- Final batch merged-tree binding and landing review or consent: reuse
  produces a normal exact-head note, so neither can be bypassed.

## 8. Questions for the security reviewer

1. Do step 4 (input-addressed check derivation, sandbox required, no
   impure-derivations feature) and pure eval together give a complete input
   closure for `nix_check` lanes? Is there an escape this misses?
2. Is the same signer level the right rule, or is "not lower" sufficient?
3. Is the bounded revocation window in §5 acceptable, or must the gate itself
   check the root's signer (a gate change)?
