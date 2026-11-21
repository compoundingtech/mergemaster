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
   train), the check and a prior evidence ID E.
2. The producer verifies E with the same verifier the gate uses, at the
   candidate's BASE: same lane, tier full, trusted signer, result pass, not too
   old, same repository.
3. The producer evaluates the drv at the candidate head the same way as a fresh
   run (signing.rs:536). Reuse is allowed only if all of these hold:
   - the drv path is byte-equal to E's `nix_derivation`;
   - `lane_definition_sha256`, `env_sha256`, `toolchain_sha256`, system and
     `nix_settings_sha256` computed at the candidate BASE equal E's;
   - the producer's own `wrapper_sha256` equals the BASE tool pin, and E's
     `wrapper_sha256` equals the BASE tool pin too (trust root unchanged);
   - the producer's signer level equals E's signer level (§5).
4. It realises the output (`nix build` of the same drv), which substitutes or
   finds it in the store, records `nix_execution=reused`, and checks
   `nix_outputs_sha256` against E's.
5. It signs a new statement for the candidate head and tree, with the normal
   exact-head subject, plus `reused_from: E` and `reuse_key` (the equal values
   from step 3).

The gate then sees an ordinary exact-head note and applies every existing
check. The decision names the reuse through `reused_from`, as the step's
acceptance requires ("reuses its verified evidence ID").

Any mismatch in step 3 gives a typed refusal, so the producer runs the check
fresh: `reuse_drv_changed`, `reuse_lane_changed`, `reuse_environment_changed`,
`reuse_tool_pin_changed`, `reuse_trust_class_changed`, `reuse_source_unverified`.

Cost: one pure `nix eval` plus a store lookup per lane and candidate. That is
seconds instead of the check's run time.

## 4. Coverage proof (Nix lanes)

Claim: when steps 2-4 pass, the check's result at the candidate equals its
result at E's head.

- The build is a function of the drv. The drv is a pure-eval function of the
  source at the head (no IFD, no impure builtins, lock not updated, user
  configuration disabled). So every source file, flake input and lock entry
  the build can read is inside the drv hash. Equal drv means equal build
  inputs.
- What runs is the lane argv applied to the drv (derivation::argv). The argv
  comes from the lane definition, bound by `lane_definition_sha256` at BASE.
- How it runs: Nix settings, store kind and daemon trust are bound by their
  hashes and checked again.
- What produced the claim: the producer binary is bound by `wrapper_sha256`
  equal to the BASE tool pin (step 3).
- Who vouches: the same signer level and a full tier (§5).

Assumption to review: the check's result depends only on the build. That is
true for Nix check derivations: their output exists only if the check passed,
and `nix_outputs_sha256` binds that output. It is false for lanes whose
command reads anything outside the drv, such as the network or host state.
Those lanes are not `nix_check` lanes and never qualify.

## 5. Trust classes

- A rebinding signer is never of a lower trust class than E's signer. This
  design requires the same signer level, which is stricter. The gate then
  applies the lane's trust_levels as usual.
- A rebind never crosses repositories: E's repository, the candidate's
  repository and the new note's repository must be equal.
- Tier must be full for E. Degraded and test tiers never qualify.
- Runner kind must be `nix`. The wrapper, sekrets and github:* runners never
  qualify.

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

1. Is the pure-eval drv a complete input closure for `nix_check` lanes? Are
   there escapes, such as `builtins.fetch*` without a hash under pure eval,
   `__impure` derivations, or `allowed-uris`?
2. Is the same signer level the right rule, or is "not lower" sufficient?
3. Is a maximum age for E needed in addition to the lane's `max_age_seconds`?
