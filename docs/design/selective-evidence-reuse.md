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
credentials are unavailable to callers, untrusted evaluation and build
processes. Evaluation runs in a credential-free isolated worker; consumer code
never executes in the signing process. A same-UID cooperative launcher/config
check is not this isolation boundary.
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
  Additionally require the signing key's BASE-pinned `v2_service_issuer`
  role and repository/service-endpoint scope (§5); level membership alone
  never authorizes a v2 root, origin or rebind.
- For a rebind, directly load R by its signed ID outside candidate-tree
  discovery (which currently filters other trees at `gate.rs:944-947`).
  Verify its signature, actual root subject/tree and `v2_service_issuer`
  role/scope under current BASE authority. Ordinary v1 evidence keys cannot
  authorize v2. Do not apply candidate exact-head/tree equality to R.
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

Slice 3 implements bounded immutable object reads, signature-to-issuer binding and
direct root lookup only; production selective reuse remains disabled. The worker
loads v2 authority from current BASE, not its legacy caller-supplied keys file.
Receipt decoding remains sealed pending the broker contract; only unit tests
substitute receipt input while exercising real Git/SSH verification and lookup.
V2 note bytes are capped at 128 KiB, notes commits at 16 KiB and notes trees at
4 KiB; missing dependencies and excess bytes refuse rather than fetch or truncate.
Version probing reuses the unbounded legacy note reader before applying v2
limits. Historical v1 notes and worker envelopes retain their uncapped admission
behavior, and v1 fingerprint metadata is best-effort only; strict fingerprint
checks remain mandatory for v2. These are conservative gate-local bounds, not an
agreed broker receipt limit.

Known #447 review exception: an optional extension value that `serde_json`
cannot materialize (for example `1e400` or nesting beyond its recursion limit)
is a policy load error, not `ReuseAuthority::Invalid`. Materializable malformed
extensions still refuse only reuse and preserve legacy policy behavior.

Slice 5 adds a pure root/rebind validator, without gate integration or admission.
It consumes current BASE configuration, the entire shared `expected_inputs`
result, verified v2 records, actual subject-object facts, an authenticated PR
context and one decision-time clock. It requires same-PR origin, direct fresh
roots, exact allowed signer levels, normalized argv and measurements, complete
key/output equality, current producer/broker authorization and finite lane age.
Broker-authority snapshots are rechecked under current BASE with no revocation
grace. Operational log digests, attempts and daemon instances are not reuse keys.

The authenticated-origin adapter is a slice-6 and external prerequisite: the
trusted GitHub/final-live-recheck path and protected service must supply verified
PR identity and single-PR train mapping, while an object adapter establishes actual
commit/tree/ordered parents and historical accepted-BASE commit presence.
`--event-file` JSON is not that authority. The private-field context and receipt
result types have no `Deserialize` implementation or production success
constructor; compile-fail examples guard that boundary. Tests alone construct
authenticated fixture contexts and accepted broker-authority snapshots, using
the existing test-only receipt decoder with real Git/SSH for note verification.

The broker receipt protocol, Linux profile enrollment and operation bindings are
still undefined (§9.7); production receipt input is always
`ReceiptContractUndefined`. No receipt envelope or authenticated-origin adapter
is invented here. The pure validator does not select a platform or reimplement
input hashing: the existing shared helper still chooses the verifier host's
system, so cross-host expected-input computation remains an integration contract
question rather than an implicit system override. The ineffective post-parse
worker-envelope v2 cap is removed; v1 remains uncapped and v2 object reads retain
their limits. The gate's unconditional production v2 refusal remains unchanged.

Slice 6 composes the worker and pure validator generically over the sealed receipt
trait. Production uses `DaemonPolicyReceipt`: it stops with
`receipt_contract_undefined` during decoding, before signature verification or root
lookup. Test-only receipt inputs and accepted-proof constructors exercise the same
orchestration with real Git objects and SSH signatures. Even complete proofs end
at an unconditional admission refusal; no switch enables reuse.

When no legacy candidate is selected, optional `selective_reuse` diagnostics retain
the existing scheduling decision and outcome. Legacy successes, failure shadowing,
timestamps and GitHub outputs are unchanged. The first immutable-ID-ordered v2
attempt supplies diagnostics, without trusting its timestamp for selection.
`root_record` appears only after verified direct lookup; sealed production receipts
therefore never expose one. Consumers reject `validated` and never claim a fresh
execution from these diagnostics. The external authenticated-origin adapter and
broker receipt contract remain prerequisites, not functionality implemented here.

## 4. Execution-policy closure prerequisite

Replace the proposed asserted `nix_sandbox_sha256` with an authenticated
`nix_daemon_policy_sha256` and attached policy receipts. Client
`nix config show` is insufficient even when `store info` says trusted.
This capability does **not** exist in the current measurement code (§2).

The Nix/host execution owner must provide a protected daemon-side execution
broker with this contract before reuse is enabled:

- It controls the actual daemon/store endpoint and mutually authenticates
  the protected signer using BASE-pinned endpoint identities. Its receipt key
  has the scoped `daemon_policy_receipt` role (§5). Missing authentication,
  transport failure or endpoint mismatch fails closed; no ambient-store or
  unsigned-receipt fallback. The caller/build cannot reach that key or an
  unrestricted alternate store endpoint. Local-store execution must use the
  same broker contract; unsupported deployments refuse reuse.
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
  The policy-generation pin and restrictions cover preparation and every child
  build, not just the final drv. Unknown policy fields/features refuse.

The signer inspects the transitive derivation graph: final check must be
input-addressed, not fixed-output, impure or `__noChroot`. Non-fixed-output
dependencies must meet the same sandbox restrictions; fixed-output fetch
dependencies may use network only with declared content-hash verification.
No ambient host mounts, unpinned network input or consumer-selected policy
escape is permitted. Fresh roots also require this profile and receipts;
old roots cannot be upgraded by assertion.

Implementation review targets: bound untrusted evaluation/receipt bytes,
parser depth, derivation-graph nodes/depth and traversal time; exceeding limits
refuses rather than truncating validation. Review credential isolation during
evaluation as well as builds, authenticated broker endpoints, fail-closed
transport and generation pinning across preparation and every child build.

This is evidence equivalence, **not** a proof that builds are deterministic.
Drv identity binds declared inputs; output NAR equality binds the realized
result, not arbitrary behavior in a hypothetical second execution. Clock,
scheduling, randomness, logs, host timing and kernel behavior may vary within
the approved profile. Lanes whose correctness needs another observation of
those effects must require `fresh` and are ineligible. `any` explicitly accepts
the prior successful result within finite age. Substituter correctness/signing
keys remain trusted. Self-measured executable digests require uncompromised
signer and broker hosts, including kernel, loader and key custody, as well as
builder integrity. Manifest equality is not remote attestation; equal content
hashes do not establish who executed a test.

## 5. Trust, origin, schema and revocation

Origin is a signed v2 predicate claim, not inferred from checkout refs or
caller environment. The protected service's trusted event adapter verifies
GitHub OIDC signature, issuer, service-specific audience, expiry, repository
identity and reviewed job/workflow SHA against its deployment allowlist. It
queries the authenticated GitHub API for the corresponding job/event and live
PR head/base/source repository; caller JSON and environment variables are not
event authority. The origin adapter is inside the service signing boundary,
with no separate adapter key; the service signs its derived origin.
It binds repository, exact subject HEAD and accepted BASE, event
kind, source repository, PR identity when applicable, and class:
`same_repository_pr`, `fork_pr`, `push`, or `local`. Missing/contradictory
identity refuses v2 issuance. Initial reuse admits only
`same_repository_pr`; train-prepared candidate heads require an authenticated
train mapping to the live PR head and accepted BASE. The gate checks this
binding against its authenticated candidate context and compares root/rebind
classes exactly. No fork-to-PR, push-to-PR or local-to-PR laundering.

Use exact signer-level equality, not "not lower"; retain BASE lane
`trust_levels` checks on both signatures, but also require the scoped
`v2_service_issuer` key role for each. Ordinary v1 evidence keys never authorize
v2 roots, origins or rebinds, even at an allowed level. Both statements require
equal logical repository identities, full tier and runner `nix`.
A v1 Nix `wrapper` note is not reclassified as an eligible root.

### Key roles, lifecycle and compromise boundary

BASE reuse policy pins each authority's key ID (public-key fingerprint), public
key, role, logical repository and authenticated service/broker endpoint scope.
V2 observations and broker receipts carry their issuer key IDs; the gate checks
the signature against the corresponding current BASE role and scope, not a
caller-selected key or signer-level membership. `v2_service_issuer` and
`daemon_policy_receipt` use separate keys, neither interchangeable with v1 keys.

The Mergemaster signing/deployment owner provisions the service key in isolated
service custody; the Nix/host owner provisions the broker receipt key in broker
custody. Neither private key is exported to workers. For planned rotation,
provision a new key ID, enroll it in reviewed BASE policy before use, and retain
both scoped IDs for an explicit finite overlap covering intended evidence age.
Switch issuance, then remove the old ID from BASE and destroy its private key;
removal immediately invalidates dependent evidence, even within its age limit.
On compromise, stop issuance, remove the affected ID/endpoint authorization
from accepted BASE without overlap or grace, replace credentials and investigate
dependent records before provisioning a separately reviewed replacement.

A compromised v2 service key defeats origin, producer and evaluation claims
together. A root and rebind signed by it are not independent witnesses; genuine
broker receipts can be re-paired with fabricated service claims. Accept this
as the trusted-service compromise boundary, not a protection supplied by
receipt signatures or root re-verification. Broker-key compromise likewise
defeats daemon-policy assurance; immediate revocation is the default (§5).

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

## 8. Decisions by Johannes

1. Eligibility (ask 962b85dc): approved. The initial origin profile is
   same-repository PRs only, and the daemon profile is Linux only. Other
   origin classes and platforms stay ineligible until reviewed.
2. Lanes and age (ask 63dca226): the deterministic dotfiles lanes
   `checks-registry`, `format`, `nixfmt`, `touched-format-lint` and
   `nix-eval` opt in, each with `max_age_seconds` 86400 (24 hours). Johannes
   accepts the §4 nondeterminism boundary for these lanes: reuse proves the
   same derivation and identical outputs, not a re-observation.
   `observability-contract` stays fresh-only. Every other lane stays
   fresh-only until it is separately reviewed.
3. Root-key revocation (ask a5dad8db): immediate, with no grace. This
   includes rebinds that were already issued.

Exact level equality plus origin equality and gate-side root verification
are design requirements, not unresolved weaker-policy alternatives.
These decisions do not enable reuse: §6 prerequisites still gate every lane.

## 9. Proposed v2 wire contract (Mergemaster-owned parts)

**Proposal for review, not an approved or implemented contract.** Selective reuse remains unconditionally disabled. Receipt representation/crypto and daemon profile remain broker-owned, TBD; this section cannot activate a lane. Code citations are relative to `crates/mergemaster-evidence/` at main 0b9082ae; design citations refer to this document at c2f9b7f3.

### 9.1 Q1 — Strict statement, origin and reuse-key schema

Keep the existing signed Git-notes commit container and in-toto envelope. Required top-level members: `_type` (literal `https://in-toto.io/Statement/v1`), `repository` (`OWNER/NAME` string), `subject` (one-element array), `predicateType` (literal `https://compounding.tech/fractal/evidence/gate/v2`), `predicate` (object). A subject has exactly `name` (full lowercase 40-hex commit ID) and `digest: {"gitTree": <40-hex tree ID>}`. Preserve sole regular note, actual subject/tree and sole subject-parent checks.

Required predicate members:
- `schema_version`: integer literal 2; `change_id`: nonempty string; `signer`: nonempty principal string; `tier`: literal `full`.
- `issuer`: exactly `{ "key_id": <OpenSSH SHA256 fingerprint>, "service_id": <BASE-pinned opaque identity string> }`.
- `producer_sha256`: lowercase 64-hex executable digest; `observed_at`, `attested_at`: RFC3339 strings denoting UTC instants (issuers emit `Z`; compare parsed instants).
- `origin`: object described below; `reuse_key`: object described below; `daemon_policy_receipt`: **broker-owned, TBD**.
- `observed`: existing tests shape: `kind: "tests"`, `runner: "nix"`, `checks` (exactly one entry, keyed by the lane/check name), `inputs` (string-to-string map). Check fields remain `command: string[]`, `exit_code: integer` (must be 0), `output_sha256: <64-hex>`.
- Optional `reused_from`: full signed notes commit ID; omitted for fresh roots. `re_attests` is not a v2 member and is rejected, including null. Optional members must be omitted, never null.

Strictness: reject unknown members in every structured object, unknown enum/version, duplicate JSON members (including maps), missing fields, nulls, noninteger numbers, malformed identifiers and out-of-bound bytes/depth/counts. `inputs` alone retains extensible string keys; it cannot carry structured authority/provenance. Explicit URI/version dispatch prevents v1/v2 downgrade. Success eligibility additionally validates measurements, commands, timestamps and scope, not merely shape.

`origin` has exactly:
- `class`: `same_repository_pr | fork_pr | push | local`;
- `repository`, `source_repository`: literal logical repository strings;
- `subject_head`, `accepted_base`: full commit IDs;
- `event_kind`: `pull_request | push | local` (train preparation remains a PR operation, not a merge-group origin);
- for PR classes only, `pull_request`: `{ "number": positive u64, "head": <live PR-head commit>, "base_ref": <literal branch name> }`;
- for prepared PR subjects only, `train_mapping`: `{ "kind": "single_pr_merge", "candidate": <subject_head>, "accepted_base": <accepted_base>, "pull_request": <same PR number>, "pr_head": <same pull_request.head> }`.
Reject PR-only members on push/local and contradictory class/repository/event combinations. Same-repository PR requires both repositories equal the statement repository. `subject_head` equals statement subject; `accepted_base` is a commit. Only `same_repository_pr` qualifies initially.

`reuse_key` has exactly `version: 1`, `check: string`, `nix_derivation: string`, `expected_inputs: {string: string}`, `nix_settings_sha256: <64-hex>`, `nix_daemon_policy_sha256: <64-hex>`, `producer: {"executable_sha256": <64-hex>, "system": string}`. The `expected_inputs` map is the **entire** shared `expected_inputs` result, not a handpicked list; optional workspace entries must match in presence and value. Compare decoded structured values exactly; no extra reuse-key digest/canonical JSON algorithm is introduced. Check consistency against each note's measured inputs and corresponding authenticated receipt. Do not include operation nonce, log digest, attestation time or daemon instance in this key.

Root: omit `reused_from`, require input modes `nix_execution=nix_command_mode=rebuild`. Rebind: require `reused_from`, modes `reused`; root must itself omit both reuse/reattest provenance. Both require equal parsed `observed_at`, same check/key/output digest and exact signer-level equality; check allowed levels independently. Enforce `observed_at <= attested_at <= now+120s` and positive representable BASE lane age for both; rebind cannot renew age. Both note and receipt authorities are checked under current candidate BASE.

Rationale: current strict fields and v1-only validator are `src/evidence/mod.rs:55–121,395–460`; note layout is `:634–680`; shared inputs are `src/gate/config.rs:998–1056`. Design 63–94,110–131,203–225,254–278 requires these extensions, direct fresh roots and exact equality. One check makes operation/receipt/output binding unambiguous.
Rejected: appending fields to v1; encoding origin/reuse inside opaque inputs; digest-only reuse keys; rebind chains; nullable provenance; multiple independently successful checks sharing one operation receipt. General multi-check v2 observations require a later version, not implicit widening.

### 9.2 Q2 — Producer identity and existing producers.json

Use `predicate.producer_sha256` as the sole authoritative measured **loaded service executable** digest. In v2 require `observed.inputs.wrapper_sha256` to equal it, retaining that existing measured-input name as a consistency binding, not as a second producer identity. `observed.inputs.system` must be present and equal `reuse_key.producer.system`; key executable digest must equal `producer_sha256`. Root/rebind must identify the same digest/system. The service owns measurements; callers cannot choose them.

Extend existing `.mergemaster/producers.json`, keeping version 1 and the existing entry shape, with one new `flavor` enum value `v2_service`. Only an entry with exact `(executable_sha256, system, flavor=v2_service)` authorizes v2. Existing `nix`/`release` entries cannot authorize it. Provenance fields retain existing validation. This is additive for new readers, deliberately rejected by older strict readers if deployed: roll out compatible verifiers/producers tooling first; do not deploy manifest enrollment in this work. No new producer document or implied authorization from `tool-pin.json`.

Rationale: signer self-measurement already exists at `src/evidence/mod.rs:546–589`; manifest shape/flavor validation and report-only wrapper matching are `src/gate/config.rs:43–142`. Existing report-only matching allows absent signed system and ignores flavor: leave that v1 reporting contract unchanged. Design 46–55,73–82,120–124,282–299 requires protected service measurement plus current manifest authorization.
Rejected: accepting either wrapper or predicate hash; reusing caller-wrapper measurements as service authentication; treating every `nix` producer as an isolated service; adding a parallel executable allowlist. The `v2_service` flavor expresses authorization intent but is not proof of isolation or remote attestation.

### 9.3 Q3 — Extend lane policy, not add a policy document

Extend existing `.mergemaster/lanes.json` version 1 with optional top-level `reuse_authorities` (array) and optional per-lane `reuse` object. Do not add a global enabled flag. Existing lane `max_age_seconds` remains the **only** age authority.

Each authority entry has exactly `key_id: string`, `public_key: string` (one OpenSSH public key, no options/comment), `principal: string` (exactly one full principal, for example `agent/<service>`; no wildcards, patterns or lists), `role: "v2_service_issuer" | "daemon_policy_receipt"`, `repository: string`, `endpoint_id: string` (nonempty opaque reviewed identity, exact comparison, no URL normalization). Enforce fingerprint/public-key consistency, unique key IDs, repository equality with policy, and different keys across roles. The principal must be well formed (`level/name`), and its level prefix must be an existing evidence trust level; BASE therefore caps the trust level that a key can claim. `endpoint_id` is the signed service/broker identity, not an unauthenticated transport locator. No wildcards or implicit repository/endpoint scope.

Lane `reuse` has exactly `{ "version": 1, "origin_profile": "same_repository_pr", "platform": "linux" }`. Its enclosing map key is the lane identifier, and the existing lane declares `max_age_seconds: positive representable u64` and `nix_check.required: "any"`. Require a matching BASE producer manifest and both authority roles/profile before even considering reuse. Broker profile enrollment details are **broker-owned, TBD**, not an implicit default Linux policy.

Decode these **new optional extension fields** as an explicit state `Absent | Valid | Invalid(reason)` before typed validation, so malformed new authority never becomes usable and does not weaken or globally replace today's v1 policy validation. Any invalid extension makes selective reuse unavailable for the policy, not partially available for its valid subset. Unknown ordinary policy/lane fields retain today's strict errors. No malformed existing producers/keys/lanes authority is downgraded to optional absence.

Keep `reuse` authorization metadata out of the existing serialized `Lane` execution-definition tuple: use a strict lane wire extension decoded into a separate per-lane authorization map, and preserve the old `Lane` serialization byte-for-byte. This avoids changing v1 `lane_definition_sha256` merely by adding reuse policy. Current BASE checks remain authoritative at each reuse decision; this metadata need not be copied into the reuse key to enforce revocation. `reuse_authorities` likewise is not an executable input. If the reviewed policy changes lane argv/inputs, the existing hash still changes normally.

Absent extension = no reuse. Invalid extension = explicit reuse refusal, with unchanged v1 exact-head behavior. Present complete valid extension still cannot enable production reuse while the unconditional prerequisite stop remains. Future enrollment is limited to the five approved lanes at 86400 seconds; no entries for other lanes, and no actual consumer edits here.

Rationale: strict policy/lane structure and existing age are `src/gate/config.rs:144–219`; BASE load and existing malformed manifest semantics `:588–608`; lane checks `:680–776`; serialized-lane hash `:1041`. Design 15–19,229–245,291–302,316–331 requires explicit reviewed BASE authority/opt-in and finite age, not a new file. This extension is interpretable without changing policy version because absence retains the complete old contract; extension itself is versioned.
Rejected: a new reuse.json (needless competing authority/document), duplicate max age inside `reuse`, automatic opt-in from `required=any`, hash-changing authorization-only fields, treating malformed extension as an empty allowlist without diagnostics, or rejecting otherwise valid legacy evidence solely because an optional new extension is invalid. Older readers reject enrollment fields; verifier-first rollout is mandatory.

### 9.4 Q4 — Note signature fingerprint and issuer binding

Retain SSH-signed Git commits. `issuer.key_id` is exactly the OpenSSH SHA256 public-key fingerprint (`SHA256:` plus canonical unpadded base64 SHA-256 of the SSH public-key blob). Require it to equal the actual verified commit key fingerprint **and** the fingerprint recomputed from the selected current BASE public key. Require the verified SSH principal **and** `predicate.signer` to each equal the selected entry's BASE-pinned `principal`; refuse otherwise. The trust level is derived only from that pinned principal (the existing `signer.split('/')[0]` lane check, `src/gate.rs:1227–1235`), so a note cannot choose its own level. Independently check the lane's allowed levels and the `v2_service_issuer` role/repository/`issuer.service_id == authority.endpoint_id`.

Construct the v2 worker's allowed-signers file with exactly one line, built only from the selected BASE entry's `principal` and `public_key`, never from a principal claimed by the note. This mirrors v1, where BASE `.st/evidence-keys` binds each principal to its key (`src/gate/config.rs:787–830`). Verify the commit, then return `{ "version": 2, "record": <ID>, "statement": <strict v2>, "verified_signer": <principal>, "verified_key_id": <fingerprint> }` through the sanitized parent/child interface. Verify actual fingerprint using Git's `%GF` result; empty/unavailable/noncanonical output refuses. A build/platform lacking reliable fingerprint reporting is unsupported for v2, not silently principal-only. No caller-selected key file grants authority; the parent supplies BASE material. Do not pass v2 through recursive v1 `re_attests` verification.

Rationale: current worker accepts a supplied BASE-created keys file (`src/gate.rs:45–60,914–935`); verifier checks `%GS` and principal but not scoped issuer fingerprint (`src/evidence/mod.rs:683–733`); sanitization is `src/gate/git.rs:16–54`. Design 110–124,220–245 explicitly requires scoped service roles and noninterchangeable keys.
Rejected: principal/level alone, trusting the signed key ID without crypto binding, trusting a matching key from any scope, v1 key fallback, ambient allowed-signers configuration. Receipt crypto/domain separation is not decided here.

### 9.5 Q5 — Authenticated candidate context, train mapping and cross-PR scope

Use an internal, non-CLI-constructible `AuthenticatedPrCandidate` with `repository: string`, `pull_request: positive u64`, `pr_head: commit`, `base_ref: string`, `accepted_base: commit`, `subject_head: commit`, `subject_tree: tree`, `source_repository: string`, `mapping: Direct | SinglePrMerge`. Populate it through the existing trusted GitHub/API path and final live recheck, never by merely accepting `--event-file` values. Local refs, push, queue and merge-group contexts cannot construct it. This is an internal type, not a new caller JSON request.

For direct candidates require `subject_head == live PR head` and omitted `origin.train_mapping`. For a train-prepared **single-PR** candidate require the service's signed `train_mapping` tuple above, agreement with authenticated live PR head/number and live accepted BASE, and an actual subject merge commit with exactly the two parents `[accepted_base, pr_head]` in that order. The protected service must authenticate preparation from its trusted event/backend mapping, not caller JSON; its signed origin is the attestation of that mapping. Gate independently verifies the tuple/parents and candidate tree. Final live PR/base changes refuse. Batch trains or another preparation shape are unsupported until an explicit reviewed mapping format exists; no generic ancestry inference substitutes for authentication.

Root origin binds the root's historical subject/BASE/PR identity; current candidate BASE authorizes its issuer, producer and profile. Do **not** require the old root's HEAD/BASE to equal current live HEAD/BASE. Initial scope is **same-PR only**: the root's `origin.pull_request.number` must equal the authenticated candidate PR number, in addition to exact repository and `same_repository_pr` class equality and complete reuse-key/output/level/profile equality. This is the case selective reuse exists for (the same PR re-validated after main moves) and is a strict subset of Johannes's same-repository-PR decision (section 8). The PR number is an origin equality check, not a reuse-key field. Cross-PR reuse within the same repository is a later widening that needs its own recorded decision. All non-PR origin classes remain ineligible.

Rationale: `src/gate.rs:229–301,336–383,418–449` supplies live authenticated repository/PR/head/base checks; `:1384–1418` alone is not a protected origin adapter. Design 203–218 requires trusted adapter, candidate binding and authenticated train mapping, while 120–128,220–225 specifies equality of class/repository rather than PR number. Single-PR prepared mapping preserves that boundary without widening merge-group/batch enforcement (design 304–312).
Rejected: trusting event JSON/environment or local branch names as signed origin; inferring PR class from a matching checkout; comparing all root/candidate origin fields (old HEAD/BASE must be allowed to differ); automatically admitting batch trains; cross-PR reuse in the initial scope (sound under full key equality, but it widens beyond the case that needs it without a recorded decision).

### 9.6 Q9 — Decision output, refusal and legacy selection

Keep existing decision `version: 1`, `decision`, `outcome`, `reason`, `record` meanings. Add optional `selective_reuse` object, omitted for all legacy-only decisions; exact members: `version: 1`, `status: "validated" | "refused" | "disabled"`, `root_record: full commit ID` (optional; set only after a verified direct root), `reason: string`. It records the selected v2 candidate's result, not discovery hints. `record` remains the candidate note ID, never the root. Do not expose an unverified claimed root through `root_record`.

On future authorized acceptance: `decision=skip`, `outcome=reused`, `reason=selective_reuse_satisfied`, `selective_reuse.status=validated`; summary explicitly says the realization reused an earlier execution. Existing v1 `reason=execution_reused` remains unchanged. While disabled: no production `validated` acceptance; report `selective_reuse_disabled` only when a v2 attempt would otherwise be selected, retain lane-mode `run` versus `refuse`, and never satisfy the lane.

Refusal reasons retain design's `reuse_source_unavailable`, `reuse_source_unverified`, `reuse_source_not_root`, `reuse_lane_ineligible`, `reuse_source_expired`, `reuse_origin_mismatch`, `reuse_producer_unauthorized`, `reuse_daemon_policy_missing`, `reuse_daemon_policy_changed`, `reuse_key_mismatch`, `reuse_outputs_mismatch`; add `reuse_authority_invalid` for malformed extensions and `reuse_candidate_unverified` for candidate signature/role failures. Shape/signature failures are not successful fallback evidence. Transport/authority verification failures are not converted into authorization. The gate does not emit `reuse_impure_derivation` based on local evaluation; only a defined authenticated admission claim can support it.

Keep v1 candidate selection/failure-shadowing byte-for-byte when no admitted v2 candidate participates. Invalid/disabled v2 notes must not shadow a valid v1 success or failure or change its timestamps. If no existing evidence satisfies, retain today's mode-dependent scheduling result and show a typed reuse refusal only as the explanation for the attempted v2 path. Future positive v2 selection must enter the normal trusted success/failure policy only after full root validation, with an explicit selection precedence test matrix before activation.

Rationale: current output schema and refusal helper `src/gate.rs:64–114`; selection/failure shadowing `:959–1069`; final reused output `:1071–1091`; existing exact-head realization reuse `:1315–1324`; consumers accept `satisfied|reused` in `genie/generic-evidence.ts:163,273` (worktree-root path). Design 96–103,125–131,266–270 requires typed refusals, root output and no fresh-run claim. Additive optional output avoids a second decision document or silent legacy semantic changes.
Rejected: replacing `record` with root ID, reusing `execution_reused` for new provenance guarantees, exposing arbitrary unverified root references as verified provenance, treating a malformed v2 note as a trusted failure, changing existing success to refusal because unrelated disabled evidence exists.

### 9.7 Broker-owner asks — Q7 and Q8 (not resolved here)

`daemon_policy_receipt` fields/envelope are **broker-owned, TBD**. Mergemaster needs these exact agreements before implementing the receipt validator:
1. Q7: versioned receipt member names/types, signed-byte envelope/algorithm/domain separation and issuer fingerprint encoding; exact bindings for signer nonce, operation ID, authenticated client/service ID, broker endpoint, drv, operation mode/status, output digest, store/instance identity and canonical policy digest.
2. Q7: how the note references/binds that exact operation, including replay prevention, nonce uniqueness and allowed receipt start/end versus root completion/rebind attestation times; which fields require equality with note claims and which must explicitly stay outside cross-host reuse-key equality.
3. Q7: policy-generation pinning and transitive-operation coverage claims the receipt authenticates; behavior on reload, child-build policy mismatch and failed operation. Gate cannot reconstruct those host facts from client configuration.
4. Q8: canonical UTF-8 JSON schema/version for all resolved effective settings, aliases/types/ordered lists/empty values, canonical digest algorithm/encoding, unknown-field behavior and shared valid/invalid golden vectors.
5. Q8: exact approved Linux profile identifier/version, architectures/features/devices, sandbox/fallback/path restrictions, substituter/key policy, builder/hook/impure restrictions and admissibility attestation fields needed by the gate.
6. Q8: embedded receipt versus immutable referenced bytes, content-ID/hash domain and dependency packaging/retention; who publishes which objects with each note; missing-object refusal behavior.
7. Q8: maximum receipt/policy bytes, JSON depth/member/list counts, signature work and operation-time/deadline bounds, with refusal rather than truncation. Mergemaster will separately bound note/worker/object reads.

Design basis: 135–187,229–234,263–265,291–302. No broker defaults, dummy receipt envelope, unsigned fallback or activation are established by this proposal.

### 9.8 Golden-vector JSON templates

These are **wire templates with placeholder tokens**, not cryptographically valid positive acceptance fixtures. Expand `C_*`/`T_*`/`R_*` to full commit/tree/note IDs, `H_*` to lowercase 64-hex digests, fingerprint/key placeholders to real fixture key material, and `D_*` to valid store derivation paths. Receipt null is intentionally non-validating: replace it with the broker-agreed signed receipt. Concrete fixture vectors must use real signatures/objects and the complete shared expected-input map.

Fresh root (the ordered maps below are presentation only; equality is structural):
```json
{
  "_type":"https://in-toto.io/Statement/v1","repository":"example/project",
  "subject":[{"name":"C_ROOT","digest":{"gitTree":"T_ROOT"}}],
  "predicateType":"https://compounding.tech/fractal/evidence/gate/v2",
  "predicate":{
    "schema_version":2,"change_id":"pr-41","signer":"agent/test-evidence-service","tier":"full",
    "issuer":{"key_id":"SHA256:TEST_SERVICE_FINGERPRINT","service_id":"service:linux-v1"},
    "producer_sha256":"H_PRODUCER","observed_at":"2026-11-22T10:00:00Z","attested_at":"2026-11-22T10:00:00Z",
    "origin":{"class":"same_repository_pr","repository":"example/project","source_repository":"example/project","subject_head":"C_ROOT","accepted_base":"C_OLD_BASE","event_kind":"pull_request","pull_request":{"number":41,"head":"C_ROOT","base_ref":"main"}},
    "reuse_key":{"version":1,"check":"format","nix_derivation":"D_FORMAT","expected_inputs":{"environment_sha256":"H_ENV","toolchain_sha256":"H_TOOL","lane_definition_sha256":"H_LANE","system":"x86_64-linux"},"nix_settings_sha256":"H_SETTINGS","nix_daemon_policy_sha256":"H_POLICY","producer":{"executable_sha256":"H_PRODUCER","system":"x86_64-linux"}},
    "daemon_policy_receipt":null,
    "observed":{"kind":"tests","runner":"nix","checks":{"format":{"command":["/trusted/nix","--extra-experimental-features","nix-command flakes","--option","accept-flake-config","false","--option","pure-eval","true","--option","allow-import-from-derivation","false","--option","builders","","--option","build-hook","","--option","max-jobs","1","--log-format","internal-json","build","--no-link","--json","--print-build-logs","--option","substitute","false","--rebuild","D_FORMAT^*"],"exit_code":0,"output_sha256":"H_ROOT_LOG"}},"inputs":{"environment_sha256":"H_ENV","toolchain_sha256":"H_TOOL","lane_definition_sha256":"H_LANE","system":"x86_64-linux","wrapper_sha256":"H_PRODUCER","nix_derivation":"D_FORMAT","nix_execution":"rebuild","nix_command_mode":"rebuild","nix_command_sha256":"H_ROOT_ARGV","nix_settings_sha256":"H_SETTINGS","nix_daemon_policy_sha256":"H_POLICY","nix_outputs_sha256":"H_OUTPUTS","nix_store":"daemon","nix_daemon_trusted":"true","workspace_clean":"true","untracked_files":"false","attempt":"1"}}
  }
}
```
Rebind (argv follows `src/evidence/derivation.rs:11–18,24–33,245–268`; digests remain placeholders):
```json
{
  "_type":"https://in-toto.io/Statement/v1","repository":"example/project",
  "subject":[{"name":"C_REBIND","digest":{"gitTree":"T_REBIND"}}],
  "predicateType":"https://compounding.tech/fractal/evidence/gate/v2",
  "predicate":{
    "schema_version":2,"change_id":"pr-41","signer":"agent/test-evidence-service","tier":"full",
    "issuer":{"key_id":"SHA256:TEST_SERVICE_FINGERPRINT","service_id":"service:linux-v1"},
    "producer_sha256":"H_PRODUCER","observed_at":"2026-11-22T10:00:00Z","attested_at":"2026-11-22T11:00:00Z","reused_from":"R_ROOT_NOTE",
    "origin":{"class":"same_repository_pr","repository":"example/project","source_repository":"example/project","subject_head":"C_REBIND","accepted_base":"C_NEW_BASE","event_kind":"pull_request","pull_request":{"number":41,"head":"C_REBIND","base_ref":"main"}},
    "reuse_key":{"version":1,"check":"format","nix_derivation":"D_FORMAT","expected_inputs":{"environment_sha256":"H_ENV","toolchain_sha256":"H_TOOL","lane_definition_sha256":"H_LANE","system":"x86_64-linux"},"nix_settings_sha256":"H_SETTINGS","nix_daemon_policy_sha256":"H_POLICY","producer":{"executable_sha256":"H_PRODUCER","system":"x86_64-linux"}},
    "daemon_policy_receipt":null,
    "observed":{"kind":"tests","runner":"nix","checks":{"format":{"command":["/trusted/nix","--extra-experimental-features","nix-command flakes","--option","accept-flake-config","false","--option","pure-eval","true","--option","allow-import-from-derivation","false","--option","builders","","--option","build-hook","","--option","max-jobs","1","--log-format","internal-json","build","--no-link","--json","--print-build-logs","D_FORMAT^*"],"exit_code":0,"output_sha256":"H_REBIND_LOG"}},"inputs":{"environment_sha256":"H_ENV","toolchain_sha256":"H_TOOL","lane_definition_sha256":"H_LANE","system":"x86_64-linux","wrapper_sha256":"H_PRODUCER","nix_derivation":"D_FORMAT","nix_execution":"reused","nix_command_mode":"reused","nix_command_sha256":"H_REBIND_ARGV","nix_settings_sha256":"H_SETTINGS","nix_daemon_policy_sha256":"H_POLICY","nix_outputs_sha256":"H_OUTPUTS","nix_store":"daemon","nix_daemon_trusted":"true","workspace_clean":"true","untracked_files":"false","attempt":"2"}}
  }
}
```
BASE policy fragment (insert into otherwise complete existing policy; not a new document):
```json
{
  "reuse_authorities":[
    {"key_id":"SHA256:TEST_SERVICE_FINGERPRINT","public_key":"ssh-ed25519 TEST_SERVICE_KEY","principal":"agent/test-evidence-service","role":"v2_service_issuer","repository":"example/project","endpoint_id":"service:linux-v1"},
    {"key_id":"SHA256:TEST_BROKER_FINGERPRINT","public_key":"ssh-ed25519 TEST_BROKER_KEY","principal":"host/test-daemon-broker","role":"daemon_policy_receipt","repository":"example/project","endpoint_id":"broker:linux-v1"}
  ],
  "lanes":{"format":{"max_age_seconds":86400,"nix_check":{"attribute":"checks.x86_64-linux.format","required":"any"},"reuse":{"version":1,"origin_profile":"same_repository_pr","platform":"linux"}}}
}
```

## Review response

Janitor's conditional GO (message/e1766cf7620a854e) resolves C1/C5/C6 and
findings 4–5; C2–C4 remain PARTIAL pending the service/key/host assumptions
and implementation review below. This revision specifies those conditions,
not implemented or independently verified capabilities.

| Review item | Resolution |
|---|---|
| C1; finding 4 (chains/age/revocation) | §3 gate enforcement and §5: verify direct fresh root under current BASE, equal times/classes, required repository, finite age; revoke root authorization immediately. |
| C2; finding 2 (signer boundary) — PARTIAL | §3, §5–§6: service-only v2 issuer role and lifecycle; trusted-service compromise defeats correlated claims. Requires protected-service implementation and review. |
| C3; finding 1 (input closure) — PARTIAL | §4–§6: authenticated broker receipts, scoped receipt-key lifecycle, host-integrity assumption and bounded-processing review targets. Daemon capability remains a prerequisite, not existing closure proof. |
| C4; finding 3 (origin) — PARTIAL | §5: origin adapter inside scoped service signing boundary, exact class equality, initial same-repository PRs only. Requires authenticated adapter implementation; service-key compromise defeats origin assurance. |
| C5; finding 5 (contract) | §2, §5: HEAD files under BASE declarations, `environment_sha256`, v2 runner `nix`, strict versioned predicate fields. |
| C6 (merge and producer foundations) | References use merged main bd3526be; §6 distinguishes landed #416/#417 report-only manifests from still-required authentication/enforcement. |
