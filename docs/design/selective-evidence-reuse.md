# Selective evidence reuse across main moves (design)

Step: step-run/01a1fdddfc677920ab1659e38c430576/reuse-gate-core (mission dotfiles-queue).
Code references are relative to `crates/mergemaster-evidence/src/` at merged
main `bd3526be7769301a2d241c974c27c3ada01c5272`, unless prefixed `README`.
This is a proposal, not a description of enabled reuse.

## 1. Problem and boundary

A main move changes a queued PR's merge HEAD and tree even when a check's
inputs are unchanged. The native PR gate requires exact commit and tree
(`gate.rs:1216-1226`). Preserve that rule: issue a new exact-head statement,
but explicitly mark its result as reused from a fresh execution.

Only BASE-declared `nix_check` lanes with freshness `any` and a positive,
finite `max_age_seconds` qualify. Keep the BASE lane object and the shared
`expected_inputs` implementation authoritative. No Nix evaluation, realization
or consumer command runs in the gate. Gate-side derivation evaluation is
rejected: it adds untrusted evaluation to a read-only decision boundary.
An unchanged gate is also rejected: a signer assertion alone cannot enforce
root verification, age, provenance or current revocation.

## 2. What a note binds today

| Input | Existing binding and limitation |
|---|---|
| Source and flake lock | Producer evaluates the exact HEAD Git URL with pure evaluation, no IFD and no lock writes/updates (`evidence/signing.rs:504-539`, `evidence/derivation.rs:124-163`). The gate checks the exact subject/tree, not Nix evaluation. |
| Lane definition | `lane_definition_sha256` hashes `[1, check, lane, definition_files]`. The lane/declarations come from BASE; regular definition files are read from HEAD, not BASE (`gate/config.rs:574-585,975-1023`). |
| Environment and toolchain | `environment_sha256`, `toolchain_sha256`, `system`: BASE environment bytes/declarations plus declared HEAD files and resolved toolchain (`gate/config.rs:975-1023`). |
| Workspace | Optional `workspace_binding=v2` and `workspace_declaration_sha256` bind the BASE inputs/scratch declaration; workspace flags are checked separately. This is not a non-Nix read closure (`gate/config.rs:1025-1033`, `gate.rs:1307-1314`). |
| Nix execution | `nix_derivation`, settings, command, output digest, store and daemon-trust claims. Gate validates their contract (`gate.rs:1261-1292`). The settings digest covers only six constants, not sandbox, substituters or trusted keys (`evidence/derivation.rs:11-18,273-275`). Client `config show` and `store info` do not attest the executing daemon's policy (`evidence/derivation.rs:71-122`). |
| Producer | Wrapper measures its own executable (`evidence/generic.rs:250-253`); signer checks the caller's digest shape and accepts its exit status (`evidence/signing.rs:693-706,751-762`). This does not authenticate the caller as that executable. |
| Trust and age | Gate checks repository when configured, full tier, allowed level, supported runner and optional age (`gate.rs:1176-1259`). No signed origin class exists in the v1 schema (`evidence/mod.rs:54-112`). |
| Runner/schema | Nix checks currently emit `runner="wrapper"` (`evidence/signing.rs:752-753`). Observation has `deny_unknown_fields`; validation requires schema 1 (`evidence/mod.rs:76-101,395-433`). New top-level predicate fields cannot silently extend v1. |

## 3. Protected execution and rebind protocol

Choose verification **inside the protected signer**, not a separate producer
capability. The signer owns evaluation, execution/realization, measurement and
statement construction. Its request accepts only repository, candidate
HEAD/BASE, check and optional immutable root evidence ID R; it accepts no
claimed producer hash, status, timestamps, origin or reuse key.
The separate-capability alternative is rejected here: it adds another issuer,
replay protocol and deployment boundary without removing protected execution.

This requires a new protected execution service: signing keys and daemon
credentials are unavailable to the caller and build processes; consumer code
executes only in the Nix build sandbox, never in the signing process. A
same-UID cooperative launcher/config check is not this isolation boundary.
The service loads only reviewed immutable producer binaries, measures the
actually loaded signer executable, and requires its digest and system to be
listed in BASE's producer manifest (§6). A deployment must prevent replacement
between measurement and execution. No generic caller-authored observation
endpoint may mint the new reuse-eligible format.

Both fresh roots and rebinds use this service:

1. Authenticate repository, candidate BASE/HEAD/tree and origin (§5), load
   BASE policy/keys/environment/producer manifest, and compute shared
   `expected_inputs` at HEAD using the BASE lane. Reject absent repository,
   non-`any` freshness or absent/zero/unrepresentable age limit.
2. For a fresh root, evaluate and admit the derivation under §4. The service
   executes the normalized `rebuild` command itself, captures status/output,
   and measures outputs and daemon-policy receipt. Sign only its own
   observation. A successful fresh root has `nix_execution=rebuild`, no
   `reused_from`, and `observed_at` equal to actual execution completion.
3. For rebind, retrieve R by immutable signed notes commit ID, never a mutable
   ref alias. Verify signature and subject/tree under **current candidate BASE**
   keys and policy. Require a successful v2 fresh root, no `reused_from` or
   `re_attests`, same check/lane, full tier, exact signer-level equality,
   required repository equality, runner `nix`, equal authenticated origin class,
   current producer authorization, and unexpired root time. A rebind is never
   a source. Missing root objects or claims refuse reuse.
4. Evaluate the candidate using the existing pure-eval/no-IFD/no-lock-update
   contract. Inspect admission (§4). Construct the shared reuse key from
   check, `nix_derivation`, every `expected_inputs` entry (including workspace
   declaration when present), `nix_settings_sha256`, authenticated daemon
   policy digest, and authenticated producer executable digest/system.
   Compare every entry to R, including absence/presence; both producer digests
   must be the same currently listed executable. No HEAD-selected lane or
   independently reimplemented input hashing.
5. The service realizes the same drv without `--rebuild`, allowing a valid
   existing store output or authenticated substitution. It captures the
   realization status itself and freshly measures the ordered output
   names/paths/NAR hashes (`evidence/derivation.rs:179-226`); require equality
   with R's `nix_outputs_sha256`. No cached caller status or output is trusted.
   Measure store, daemon trust, toolchain/closure, workspace and policy for
   this operation; do not copy operational claims from R.
6. Sign an exact candidate HEAD/tree v2 note, runner `nix`,
   `nix_execution=nix_command_mode=reused`, and the normal normalized reused
   argv. Copy only R's `observed_at`; set `attested_at` to this operation's
   completion, cite R and the equal reuse key. Its output/log digest describes
   this realization, not a fabricated rerun of R's logs.

Typed refusal reasons distinguish `reuse_source_unavailable`,
`reuse_source_unverified`, `reuse_source_not_root`, `reuse_lane_ineligible`,
`reuse_source_expired`, `reuse_origin_mismatch`, `reuse_producer_unauthorized`,
`reuse_daemon_policy_missing`, `reuse_daemon_policy_changed`,
`reuse_impure_derivation`, `reuse_key_mismatch`, `reuse_outputs_mismatch`.
A reuse refusal may schedule a fresh execution; it never silently satisfies
the lane. Signing/authority failures are errors, not permission to weaken
execution isolation or issue a v2 note through the old signer.

### Gate enforcement

Extend the gate's existing signature worker and object-only input checks
(`gate.rs:906-957,1187-1324`); do not merely trust step 3:

- Verify the candidate normally, including exact HEAD/tree, current BASE
  signature, lane inputs, normalized argv, success and workspace claims.
- For a rebind, directly load R by its signed ID outside candidate-tree
  discovery (which currently filters other trees at `gate.rs:944-947`).
  Verify its signature and actual root subject/tree under current BASE keys.
  Do not apply candidate exact-head/tree equality to R.
- Require v2 root-only provenance, `rebuild`, success, no `reused_from` or
  `re_attests`; compare check, full tier, runner `nix`, exact signer level,
  repository, origin class, complete reuse key and output digest. Check both
  producer identities against current BASE manifest and daemon receipt
  signatures against current BASE authority (§4).
- Require positive finite lane age, equal parsed root/rebind `observed_at`,
  `observed_at <= attested_at <= now + 120s`, and age within that lane's limit
  for both at decision time. Future-root handling retains the existing
  120-second skew bound (`gate.rs:1235-1244`); rebind cannot renew age.
- Refuse a missing/unverifiable/revoked root, stale policy/key authority, any
  unequal claim or unapproved origin. Return the cited root ID in the decision.
  No recursive chain traversal or Nix subprocess is needed.

## 4. Execution-policy closure prerequisite

Replace the proposed asserted `nix_sandbox_sha256` with an authenticated
`nix_daemon_policy_sha256` and attached policy receipts. Client
`nix config show` is insufficient even when `store info` says trusted.
This capability does **not** exist in the current measurement code (§2).

The Nix/host execution owner must provide a protected daemon-side execution
broker with this contract before reuse is enabled:

- It controls the actual daemon/store endpoint, authenticates the protected
  signer, and owns a receipt key whose public authority is enrolled in BASE
  reuse policy. The caller/build cannot reach that key or an unrestricted
  alternate store endpoint. Local-store execution must use the same broker
  contract; unsupported deployments refuse reuse.
- It measures the **effective daemon policy after per-operation overrides**,
  including sandbox/fallback, sandbox and extra-sandbox paths, substituters
  and extra-substituters, trusted-public-keys and extra-trusted-public-keys,
  signature requirements, enabled experimental/impure features, builders,
  hooks, platform/system features, and Nix daemon executable/version. All
  includes/defaults/aliases must be resolved. Version-one canonical UTF-8 JSON
  sorts keys, normalizes setting types, preserves ordered lists, and includes
  empty values; hash those bytes, not a caller-supplied digest.
- Its signed receipt binds a signer-generated nonce, operation ID, drv,
  authenticated client, daemon instance/store identity, canonical policy,
  policy digest, start/end times, operation mode/status and output digest.
  Pin the policy generation for the whole operation; a reload/change aborts
  rather than signing two snapshots around an unobserved interval. The signer
  verifies the receipt before constructing the note; the gate verifies it too.
  Nonces prevent replay into another operation. Instance/nonce/time are receipt
  metadata, not cross-host reuse-key equality fields.
- Initial admissible profile: supported Linux sandbox with `sandbox=true`,
  fallback false, no extra host bind mounts/sandbox paths, no remote builders
  or build hooks, no impure/dynamic derivation features. Required virtual
  devices/proc and platform features are fixed by the profile version.
  Substitution requires signatures from the measured explicit key allowlist;
  substituters/keys must equal the root's policy even if a store hit occurs.
  The broker applies these restrictions to root preparation and all child
  builds, not just the final drv. Unknown policy fields/features refuse.

The signer inspects the transitive derivation graph: final check must be
input-addressed, not fixed-output, impure or `__noChroot`. Non-fixed-output
dependencies must meet the same sandbox restrictions; fixed-output fetch
dependencies may use network only with declared content-hash verification.
No ambient host mounts, unpinned network input or consumer-selected policy
escape is permitted. Fresh roots also require this profile and receipts;
old roots cannot be upgraded by assertion.

This is evidence equivalence, **not** a proof that builds are deterministic.
Drv identity binds declared inputs; output NAR equality binds the realized
result, not arbitrary behavior in a hypothetical second execution. Clock,
scheduling, randomness, logs, host timing and kernel behavior may vary within
the approved profile. Lanes whose correctness needs another observation of
those effects must require `fresh` and are ineligible. `any` explicitly accepts
the prior successful result within finite age. Substituter correctness/signing
keys and protected host/kernel integrity remain trusted; equal content hashes
do not establish who executed a test.

## 5. Trust, origin, schema and revocation

Origin is a signed v2 predicate claim, not inferred from checkout refs or
caller environment. The protected service's trusted event adapter verifies
GitHub OIDC signature, issuer, service-specific audience, expiry, repository
identity and reviewed job/workflow SHA against its deployment allowlist. It
queries the authenticated GitHub API for the corresponding job/event and live
PR head/base/source repository; caller JSON and environment variables are not
event authority. The service signs the derived origin in its observation.
It binds repository, exact subject HEAD and accepted BASE, event
kind, source repository, PR identity when applicable, and class:
`same_repository_pr`, `fork_pr`, `push`, or `local`. Missing/contradictory
identity refuses v2 issuance. Initial reuse admits only
`same_repository_pr`; train-prepared candidate heads require an authenticated
train mapping to the live PR head and accepted BASE. The gate checks this
binding against its authenticated candidate context and compares root/rebind
classes exactly. No fork-to-PR, push-to-PR or local-to-PR laundering.

Use exact signer-level equality, not "not lower"; retain BASE lane
`trust_levels` checks on both signatures. Both statements must have required
equal logical repository identities, full tier and runner `nix`. Different
principals at the same permitted level may sign only through the protected
service. A v1 Nix `wrapper` note is not reclassified as an eligible root.

Introduce predicate URI `https://compounding.tech/fractal/evidence/gate/v2`
and `schema_version=2`, keeping the in-toto Statement/v1 envelope. Define a
separate strict v2 decoder, explicitly dispatched by URI/version:

- Predicate fields: existing observation fields plus required `origin`,
  required `attested_at`, required `reuse_key` (a versioned structured map),
  required daemon-policy receipt, and optional `reused_from` (full signed
  notes commit ID). Fresh eligible roots carry the key/receipt too but omit
  `reused_from`; they do not use `re_attests`.
- `observed.inputs` retains existing measured input names and gains
  `nix_daemon_policy_sha256`. Structured origin, receipt and provenance do
  not hide in the opaque v1 inputs map.
- Emit `runner="nix"` for v2 Nix observations. Update producer, verifier,
  decision output and consumers together. Never append predicate fields past
  v1's `deny_unknown_fields`, reinterpret v1 as v2, or downgrade a rebind.
  Existing v1 exact-head evidence remains governed by its current contract,
  but can never serve as a selective-reuse root.

At every gate decision, current BASE keys/policy must still authorize **both**
root and rebind, both producers and daemon receipt authorities. Root-key
revocation invalidates even a rebind signed before revocation; finite age is
not a revocation grace period. Retention of evidence bytes for audit does not
retain authorization. A revocation grace policy requires separate explicit
approval; default refuse. Missing root objects likewise refuse, regardless of
an unexpired signed rebind.

## 6. Landed foundations and remaining prerequisites

Main includes #416/#417: `.mergemaster/producers.json` is read from BASE and
validated (`gate/config.rs:43-142,565-573`). Its digest/system match is
**report-only**, not producer authentication or authorization; it does not
compare flavor (`README:665-705`). `tool-pin.json` identifies the verifier,
not an executable producer allowlist. `producers measure` and the reusable
workflow produce/reproduce manifest bytes, including separately verified
release attestations (`README:707-738,740-762`). They do not authenticate a
running evidence caller. Do not describe those landed changes as enforcement.

Required before enabling any lane:

| Capability | Responsible owner | Acceptance boundary |
|---|---|---|
| Protected execution/signing service and authenticated origin adapter | Mergemaster evidence/signing owner with host/CI deployment owner | No caller status/digest authority; isolated keys; service measures executing producer and owns root/rebind operation (§3, §5). |
| Daemon-policy broker, receipt schema and enrolled keys/profile | Nix/host execution owner with security review | Effective policy bound to entire operation; no client-config substitute (§4). |
| Strict v2 format and gate root validation | Mergemaster evidence/gate owner | Current BASE verification, direct root lookup, finite age, equality checks, origin/receipt validation; no Nix in gate (§3, §5). |
| Reuse-only manifest enforcement and BASE policy rollout | Mergemaster gate/policy owner | Require manifest plus signed system and listed measured producer for both notes; existing report-only matching alone cannot authorize (§3). Explicit BASE profile/receipt keys and lane opt-in; malformed/absent authority refuses reuse. |
| Root/receipt object availability | Evidence transport/storage owner | Publish immutable root and receipt bytes with rebind, retain through lane lifetime; gate verifies IDs/signatures, never trusts transport. |

No implementation is included here. Until all prerequisites land, selective
reuse stays disabled; report-only producer manifests remain report-only.

## 7. Out of scope

- Non-Nix lanes: no read-closure key; no selective reuse.
- Merge-group enforcement, push identical-tree transfer and local evidence:
  unchanged; not admitted by this initial origin profile.
- Final batch merged-tree binding and landing review/consent: unchanged.
  A reused note still needs the exact candidate HEAD/tree and normal gate.
- Cross-level reuse, rebind chains and pre-v2 root promotion: prohibited,
  rather than compatibility shims.

## 8. Questions for Johannes

1. Approve the initial same-repository-PR-only origin profile and Linux-only
   daemon profile? Other classes/platforms remain ineligible until reviewed.
2. Which lanes accept the nondeterminism boundary in §4, and what positive
   finite age should each opt-in declare? No unbounded default.
3. Is any root-key-revocation grace needed? Default is immediate refusal at
   the gate, including already-issued rebinds. Any exception needs a separately
   approved policy naming scope, duration and revocation authority.

Exact level equality plus origin equality and gate-side root verification
are design requirements, not unresolved weaker-policy alternatives.

## Review response

| Review item | Resolution |
|---|---|
| C1; finding 4 (chains/age/revocation) | §3 gate enforcement and §5: verify direct fresh root under current BASE, equal times/classes, required repository, finite age; revoke root authorization immediately. |
| C2; finding 2 (signer boundary) | §3, §6: protected service owns execution and rebind; reject self-reported digest/status as authentication. |
| C3; finding 1 (input closure) | §2, §4: authenticated executing-daemon receipts include sandbox paths, substitution keys/endpoints and impure features; missing capability refuses reuse; explicit nondeterminism boundary. |
| C4; finding 3 (origin) | §5: authenticated signed origin with exact class equality; initial same-repository PRs only. |
| C5; finding 5 (contract) | §2, §5: HEAD files under BASE declarations, `environment_sha256`, v2 runner `nix`, strict versioned predicate fields. |
| C6 (merge and producer foundations) | References use merged main bd3526be; §6 distinguishes landed #416/#417 report-only manifests from still-required authentication/enforcement. |
