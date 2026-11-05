# Exact-tree CI attestations

## Scope and trust boundary

This proposal separates keyless CI payloads from a privileged signer and adds an
explicit `gate --event merge_group` decision. Existing identical-tree push reuse
remains unchanged. Action-key-based reuse is not part of this change. No KMS or
additional paid service is required by the protocol.

A malicious contribution controls candidate source, build definitions, tests,
logs, manifests, caches and any candidate workflow edits. It can deliberately
make its own tests pass or lie in its own output: this is hosted-CI execution
trust, not a proof of test quality or a sandbox-escape guarantee. It must not
claim a different authorized tree, recipe, repository, run, attempt or job.
GitHub, the selected runner platform, accepted BASE, and their administrators
are trusted. The signing key never enters a candidate-executing job.

Payload workflows invoke immutable, accepted reusable workflow/action revisions.
They run BASE-declared lanes against the selected candidate tree and report
Buck2/Nix action keys, result and log digest. The signer never executes candidate
code, restores executable candidate caches, evaluates candidate build definitions,
or executes extracted artifacts. It independently resolves Git objects and BASE
policy; downloading a manifest does not make its assertions authoritative.

### Lane-definition change routing

Lane-definition changes require a person-operated signer's record; automated
attestation never covers a lane whose definition differs between BASE and
candidate. Other lanes in this profile use the BASE-only automated attestation.

The gate independently compares the canonical definition manifests at BASE and
candidate, including declared paths, content and executable modes; a candidate
claim hash is not the comparison authority. For a changed lane, records from the
automated tier are ineligible with `definition_changed_requires_person_tier`.
Only a BASE-designated person-operated principal may authorize that changed
candidate definition, with all normal signature/tree/recipe checks still in force.
Do not infer person operation from an arbitrary non-automated key. The signer also
refuses automated coverage of changed definitions; the gate repeats the check
even if an automated signature is otherwise valid.

## Authenticated identity and artifact boundary

GitHub OIDC supplies repository IDs, run ID, run attempt, event, workflow identity
and `check_run_id`. Reusable jobs additionally expose `job_workflow_ref` and
`job_workflow_sha`; require both the approved path and immutable revision, not a
mutable `@main` reference. These identify job context, not checkout
([OIDC][1]; [reusable workflows][2]).
A reusable-workflow `uses:` cannot interpolate an arbitrary BASE expression:
its immutable revision must be pinned by an accepted dispatcher/configuration.

Authenticate the triggering run through the attempt-specific run and Jobs APIs.
Require repository ID, run ID, attempt, workflow ID/path and referenced reusable
revisions to match BASE policy. Join a token's `check_run_id` to the job API's
`check_run_url`; do not assume it equals the Actions job ID. Require the expected
job to be completed and use its independently fetched conclusion.[3]

The artifact API authenticates artifact ID, run membership and a nullable SHA-256
digest. It does **not** provide producing job or attempt membership. Names,
timestamps, `attempt-2` suffixes and a manifest's self-reported IDs cannot fill
this gap. Refuse absent digests; hash the downloaded archive before bounded,
fixed-member extraction, and separately hash the manifest and logs.[4]

### Accepted producer proof v1

A producer first uploads an immutable result artifact. It then emits the canonical
producer receipt specified below, excluding all signer-added fields. The job
requests a GitHub OIDC JWT with the exact audience
`urn:mergemaster:payload-receipt:v1:sha256:<receipt-sha256>` and uploads receipt
plus JWT as a separate, untrusted transport artifact. No payload private signing
key is introduced. Payload OIDC permissions must never authorize the SSH secret.

This protocol uses GitHub's documented custom audience; it is **not** a
GitHub-standard artifact attestation. The signed audience commits the job to
these receipt bytes. GitHub does not validate the receipt's contents. Verify the
JWT with the pinned GitHub issuer/JWKS, approved algorithm and key ID; require
exact string audience, valid time bounds and expected claims. Canonical v1 JSON
rejects duplicate/unknown fields and uses sorted keys, integer IDs and no
insignificant whitespace. A different job can request the same audience but
cannot forge the required repository/run/attempt/check-run/workflow claims.[1]

Every receipt selector must agree with authenticated identity and API metadata.
Resolve candidate commit-to-tree independently from Git objects and the accepted
event/dispatcher binding; JWT `sha`, run `head_sha`, signer `github.sha` and an
arbitrary checkout are not interchangeable. Refuse an event without a provable
candidate mapping. Compare BASE recipe and action-key backend declarations;
action-key values remain authenticated assertions by the payload engine, not
independently re-executed build analysis. They grant no cross-tree reuse.

Record an unsuccessful job as failure even if its receipt claims success.
Do not equate a success conclusion with every step passing: BASE recipes must
not ignore required-lane failures. An identical receipt is idempotent, not a new
execution; a different attempt cannot inherit its predecessor's receipt.
Initially reject expired producer tokens. Queue delays can therefore require a
new payload run; no historical-token or timestamp guarantee is assumed.

`mergemaster_evidence::evidence::signer_input::derive_expected` derives the
producer verifier's expectations from BASE policy, independently resolved Git
objects, attempt-specific API snapshots and the downloaded archive's SHA-256.
`verify_signer_input` composes that derivation with the producer proof and returns
the independently observed successful job conclusion. Failed/incomplete jobs
refuse `payload_failed`; neither function provisions keys or executes artifacts.
Direct source derivation supports merge-group queue SHAs for BASE policy's
protected branch and pushed SHAs. Queue refs require exactly
`gh-readonly-queue/<protected-branch>/pr-<positive-decimal>-<40-or-64-lowercase-hex>`,
with no leading zero in the PR number or nested branch suffix;
event authorization remains a separate preflight gate (Stage 1 does not authorize
push signers). Pull-request derivation refuses `source_unbound`: the PR head
commit cannot stand in for its OIDC merge commit.

### Standard artifact attestations

GitHub attestations are useful for authenticated artifact digest, reusable builder
identity and run/attempt provenance. The standard SLSA predicate does not contain
payload job/check-run ID, exact checkout tree, BASE recipe or test result. A
custom predicate is still a producer assertion. Attesting a downloaded payload
in the signer proves signer provenance, not original payload provenance.[5]
They can corroborate the producer receipt, but cannot silently replace its
missing bindings. Both keyless attestation and the proposed receipt need
`id-token: write`; neither proves the truth of hostile test output.

## Signer credential options

### A. Namespace Vault secret and scoped OIDC federation
Option A is closed. Reopen only after written provider confirmation of the
single-object restriction and elimination of the bypass paths below.


Namespace documents encrypted, versioned Vault secrets and object-specific
`describe`/`reveal` grants. However, its runner workload tokens have broad default
workspace access. Generic OIDC trust relationships match issuer/subject/audience,
but the published supported-issuer list does not establish GitHub support or
immutable-workflow restrictions on a Vault grant.[6][7]

Deployment is blocked until the provider confirms a GitHub trust policy binding
repository ID, approved signer workflow revision, event/environment and audience
to only one secret, without bypass through automatic runner credentials, broad
GitHub-App federation or a candidate-selected permissive runner profile. Payload
profiles must not have another route to Vault. Merely omitting `id-token: write`
or assigning a Restricted profile is not sufficient admission control.[8]
No unsupported policy syntax or entitlement to enterprise controls is assumed.

### B. Default-branch `workflow_run` signer and GitHub environment secret
Option B is chosen. The initial consumer is `compoundingtech/fractal`:
environment `mergemaster-attestation`, secret `MERGEMASTER_ATTESTATION_KEY`.


A signer workflow stored on the default branch handles `workflow_run: completed`.
GitHub documents its SHA/ref as the default branch and permits this follow-up to
use secrets even when the triggering payload could not. Fetch the triggering
`workflow_run.id`, not the signer's own run ID. Preflight obtains payload
repository, workflow path/ID, event, `head_sha` and `run_attempt` from GitHub API
metadata, never artifacts. Pin the API-selected attempt, fetch its exact run/jobs,
and require the producer proof to match it. Recheck identity/attempt before signing;
a racing rerun refuses rather than selecting a convenient receipt. A workflow-name
filter alone is not authorization.[9]

Store the SSH key only in that environment with **Selected branches: main**,
Branch type only: no wildcards, tags, PR pattern or queue exception. Policies
match the run's `GITHUB_REF`: a `workflow_run` signer qualifies; ordinary PR and
`merge_group` refs do not. Merely referencing the environment does not bypass
the deployment policy.[10]
Do not use "Protected branches only": with no branch protections it permits all
branches. Disable administrator bypass unless explicitly part of the trust model.

| Job context | Environment policy outcome |
| --- | --- |
| Ordinary `pull_request` / PR merge ref | Denied |
| `merge_group` / queue ref | Denied |
| Candidate-executing Namespace payload | Must have no secret access |
| Default-branch job | Eligible; BASE-trusted code |
| `pull_request_target` / base-branch ref | Eligible; BASE-trusted code |
| `workflow_run` signer / default-branch ref | Eligible after origin preflight |

No `pull_request_target` workflow may exist in the consumer repository unless
reviewed as BASE-trusted code. An environment rule alone does not reject a
`workflow_run` from a fork/non-main origin: its own ref is still main.
An unprivileged BASE-only preflight is mandatory, with `needs:` plus `if:` gating
the environment-bearing job. Stage 1 allows only the approved payload workflow
path/ID, triggered by same-repository `pull_request` or `merge_group` on
`gh-readonly-queue/main/*`, with API head SHA equal to the expected candidate.
Fork PRs, other workflows (including renamed/copied files), pushes and
`workflow_dispatch` are refused before scheduling the protected job. A PR or
queue candidate ref is not itself a forbidden controller origin.
Secret presence in a BASE-code signer is acceptable; candidate code must never
read it, and a disallowed origin must never receive a signed record.

This is branch authorization, not workflow authorization: all default-branch
workflows and especially `pull_request_target` are trusted code. They must not
execute candidate code while referencing the environment. Inspect dispatch inputs,
actions and cache use. The signer checks its own OIDC workflow/repository identity
and uses only an accepted, immutable verifier revision. Default-branch origin is
not proof that the signer's SHA equals the payload's accepted BASE; bind both and
require BASE's approved signer policy. Prefer a separate GitHub-hosted signer job
for this option; Namespace may also host it if its other credential paths are safe.

Option B avoids the unconfirmed Namespace Vault policy. Existing plan support
for environment protection remains required; no paid upgrade or workflow-level
isolation is implied. Both options require the same producer/run/artifact checks.

## Signed record and key lifecycle

Keep the in-toto subject's commit and `gitTree` digest and version the CI binding.
The **producer receipt** carries: repository/owner IDs; accepted BASE; candidate
commit/tree; lane; BASE lane/environment/recipe digests; payload workflow
path/revision; producer run ID, attempt, job ID and check-run ID; result artifact
ID/archive digest; manifest digest; action-key map; log digest; and claimed result.
It cannot contain a digest of its own later-issued producer proof.

The **signer adds**: verified producer-proof digest; action-key-map digest;
independently observed job result and verification time; signer workflow
path/revision, repository/run/attempt/job identity; and signing principal/key
generation. Every producer claim is checked before inclusion. Preserve existing
clean-input and freshness contracts: signing cached Nix output is not fresh execution.

Use a dedicated SSH Ed25519 key, compatible with current Git-signed records.
Enroll only its public key in accepted BASE under a new principal level such as
`namespace/ci-v1`, separate from `agent/` and `host/`; lanes explicitly opt in to
`namespace`. This is signer authorization, not a replacement for the existing
`full`/`degraded`/`test` observation-quality field. Use one generation per key;
never reuse a personal or developer-machine key. Generate the private key in
memory on a trusted machine; provision it without a plaintext file or message.
Load it into an ephemeral `ssh-agent` through stdin, addressed by its public key.
No private-key file, log, artifact or cache is allowed; destroy the agent on exit.

Rotation adds the new public generation to accepted BASE, updates the protected
secret, proves a new attestation, then removes the old public key. Revocation
removes enrollment from the currently accepted BASE and prevents future reuse
under that policy; it does not mutate historical signed objects. Secret access
and policy changes require an administrator and an auditable inventory update.

## Merge-queue gate semantics

`gate --event merge_group` is explicit and requires lane event opt-in. For
`checks_requested`, independently bind repository, `merge_group.head_sha`,
`head_ref`, `base_sha` and `base_ref`. GitHub defines `base_sha` as the group's
parent commit, not necessarily the current protected-branch tip.[11] Keep that
event parent separate from accepted BASE: obtain the trust anchor from the live
protected target, require it to be an ancestor of the group, and load keys/lanes
only from that accepted commit, never an unmerged queue predecessor. Resolve the
actual group tree and recompute bindings. Never substitute the PR head or
signer's default-branch checkout.

Recheck the live queue ref/head and protected target/base before publication;
stale or superseded groups cannot satisfy a required check. Apply protected-path
checks to the entire BASE-to-group tree diff. Unhandled protected edits refuse;
merge-queue membership alone is not human approval. Only exact-tree, trusted,
policy-matching evidence can skip a lane; retain newest-failure precedence,
maximum age and explicit reuse policy. Missing evidence runs the configured real
fallback or refuses. Report-only decisions never publish a required success.

## Refusals and delivery gates

Stable refusal codes: `oidc_invalid`, `identity_unbound`, `foreign_run`,
`wrong_attempt`, `wrong_job`, `wrong_recipe`, `tree_mismatch`, `source_unbound`,
`artifact_unbound`, `artifact_digest_mismatch`, `action_keys_unbound`,
`payload_failed`, `signer_policy_mismatch`, `signing_unavailable`,
`event_not_allowed`, `stale_merge_group`,
`definition_changed_requires_person_tier`, and existing `protected_paths`.
Unsupported/missing provider authorization refuses; no local-key fallback.
Transport failures and malformed configuration remain errors, not satisfaction.

1a delivers signer verification and refusal tests for wrong tree, attempt, recipe
and foreign run first. Report-only rollout (1b) additionally requires real-run
negative-access proofs for ordinary PR, merge-group and Namespace payload jobs.
Preflight negatives include a fork PR, feature-branch push, branch dispatch,
renamed/copied payload workflow, and receipt from another rerun attempt.
Trusted/default-branch and reviewed `pull_request_target` rows are eligible, not
negative-access expectations. Every signature binds the API-selected payload
attempt. The signer never downloads candidate caches or executes artifacts:
BASE code parses data only. Prove trusted in-memory key generation/provisioning
and absence of the private key from files, logs and messages.

Enforcement follows these proofs and live queue checks. Key provisioning is a
separate administrator request; this design does not create a secret or authorize deployment.

## Sources

[1]: https://docs.github.com/en/actions/reference/security/oidc
[2]: https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows
[3]: https://docs.github.com/en/rest/actions/workflow-jobs
[4]: https://docs.github.com/en/rest/actions/artifacts
[5]: https://github.com/actions/toolkit/blob/main/packages/attest/src/provenance.ts
[6]: https://namespace.so/docs/architecture/storage/secrets.md
[7]: https://namespace.so/docs/reference/cli/auth-trust-relationships-add.md
[8]: https://namespace.so/docs/workspaces/access.md
[9]: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run
[10]: https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments#deployment-branches-and-tags
[11]: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#merge_group
