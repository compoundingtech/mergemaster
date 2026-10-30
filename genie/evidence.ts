// Workflow adapters moved from compoundingtech/fractal e83871ec919f95b3b3e2a9a1cd211c2ac37babda.
// Policy, event selection and lane wiring remain consumer-owned. Tools still come from BASE.
export type WorkflowValue = string | number | boolean | undefined | readonly WorkflowValue[] | { readonly [key: string]: WorkflowValue }
export type WorkflowObject = { readonly [key: string]: WorkflowValue }
export interface Actions {
  readonly checkout: string
  readonly uploadArtifact: string
  readonly downloadArtifact: string
}
export interface GateOptions {
  readonly checks: readonly string[]
  readonly runInputs?: Readonly<Record<string, { readonly needs: readonly string[]; readonly values: Readonly<Record<string, string>> }>>
  readonly actions: Actions
  readonly runner?: string
}
const evidenceGateOutcomes = [
  ['satisfied', 'evidence satisfied by existing note'],
  ['degraded', 'evidence existing note is degraded'],
  ['no_note', 'evidence no note'],
  ['rejected', 'evidence note rejected'],
  ['unavailable', 'evidence verifier unavailable'],
] as const
export const evidenceGateJobs = ({ checks: evidenceGateChecks, runInputs: evidenceGateRunInputs = {}, actions, runner = 'ubuntu-latest' }: GateOptions): WorkflowObject => Object.fromEntries(evidenceGateChecks.map((check) => [`evidence-gate-${check}`, {
  name: `evidence-gate-${check}`,
  ...(evidenceGateRunInputs[check] ? { needs: evidenceGateRunInputs[check].needs } : {}),
  'runs-on': runner,
  'timeout-minutes': 5,
  'continue-on-error': true,
  permissions: { contents: 'read' },
  // The decision the check jobs act on comes from the marker step below, not from the gate step: skip=true can
  // exist only if the marker already ran, so the observer, which keys on the marker, can never miss a skip.
  // `line` is the gate's decision line, for evidence-presign-notice only; nothing decides a skip from it.
  // `refuse` likewise comes only from its marker step: an unsigned signed-only pull request, refused instead of run.
  outputs: { skip: '${{ steps.taken.outputs.skip }}', record: '${{ steps.taken.outputs.record }}', line: '${{ steps.gate.outputs.line }}',
    refuse: '${{ steps.refused.outputs.refuse }}', refusal: '${{ steps.refused.outputs.refusal }}' },
  steps: [
    { uses: actions.checkout, with: { 'persist-credentials': false } },
    {
      name: 'Look for an existing evidence note',
      id: 'gate',
      env: {
        CHECK: check,
        REPOSITORY: '${{ github.repository }}',
        BASE_SHA: "${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha || (github.event_name == 'push' && github.event.before) || '' }}",
        HEAD_SHA: '${{ github.sha }}',
        HEAD_REPOSITORY: "${{ github.event.pull_request.head.repo.full_name || ((github.event_name == 'merge_group' || github.event_name == 'push') && github.repository) || '' }}",
        EVENT_NAME: '${{ github.event_name }}',
        PR_NUMBER: '${{ github.event.pull_request.number }}',
        // A pull request run may ask about the pull request HEAD's tree (scripts/ci-evidence-gate, choose_tree); these are
        // the payload facts it checks that head and its authors against. All empty outside a pull request.
        PR_HEAD_SHA: '${{ github.event.pull_request.head.sha }}',
        PR_USER: '${{ github.event.pull_request.user.login }}',
        PR_DRAFT: '${{ github.event.pull_request.draft }}',
        ACTOR: '${{ github.actor }}',
        TRIGGERING_ACTOR: '${{ github.triggering_actor }}',
        RUN_ID: '${{ github.run_id }}',
        RUN_ATTEMPT: '${{ github.run_attempt }}',
        ...(evidenceGateRunInputs[check] ? { RUN_INPUTS: JSON.stringify(evidenceGateRunInputs[check].values) } : {}),
      },
      // The gate is taken from the accepted base, like the verifier, so a change cannot rewrite the
      // script that decides whether it is skipped. No gate at the base, or any failure: run the check.
      // For a pull_request run that base is the first parent of the checked-out merge (refs/pull/N/merge): the base tip GitHub
      // merged the head into, which the gate judges. The payload's base.sha is not: a reopen or ready_for_review keeps the one from
      // the last open or push, and on 2026-10-28 a reopen ran a gate from before .st/evidence-signed-only.json existed (#4144). The
      // payload's base goes to the gate as EVENT_BASE_SHA, which refuses a signed-only opener's run when it is not in that history.
      run: `gate_base="$BASE_SHA"; if [ "$EVENT_NAME" = pull_request ]; then set -- $(git cat-file -p HEAD | sed -n 's/^parent //p'); if [ "$#" = 2 ] && [ "$2" = "$PR_HEAD_SHA" ]; then gate_base=$1; fi; fi; export EVENT_BASE_SHA="$BASE_SHA" BASE_SHA="$gate_base"; git fetch --no-tags --depth=1 -q origin "$BASE_SHA" && git show "$BASE_SHA:scripts/ci-evidence-gate" > "$RUNNER_TEMP/ci-evidence-gate" && python3 "$RUNNER_TEMP/ci-evidence-gate" || { printf 'outcome=unavailable\\nskip=false\\nrecord=-\\n' >> "$GITHUB_OUTPUT"; echo "evidence-decision v1 check=$CHECK decision=run outcome=unavailable reason=no-gate-at-base run=$RUN_ID"; }`,
    },
    ...evidenceGateOutcomes.map(([outcome, name]) => ({
      name,
      if: `steps.gate.outputs.outcome == '${outcome}'`,
      run: `echo ${name}`,
    })),
    // Fixed name: a decision to skip was taken. The observer must not record a check whose gate ran
    // this step as a fresh finished run, or one real run would keep refreshing its own skips.
    {
      name: 'evidence skip taken',
      id: 'taken',
      if: "steps.gate.outputs.skip == 'true'",
      env: { RECORD: '${{ steps.gate.outputs.record }}' },
      // The outputs are the LAST thing this step writes: if anything before them fails, there is no skip.
      run: `echo evidence skip taken && printf 'skip=true\\nrecord=%s\\n' "$RECORD" >> "$GITHUB_OUTPUT"`,
    },
    // Fixed name: the check is refused, not run (an unsigned signed-only pull request). Its outputs, too, are the last thing written.
    {
      name: 'evidence refused: not signed',
      id: 'refused',
      if: "steps.gate.outputs.refuse == 'true' && steps.gate.outputs.skip != 'true'",
      env: { REFUSAL: '${{ steps.gate.outputs.refusal }}' },
      run: `echo "$REFUSAL" && printf 'refuse=true\\nrefusal=%s\\n' "$REFUSAL" >> "$GITHUB_OUTPUT"`,
    },
  ],
}]))

export const evidencePresignNoticeJob = ({ checks: evidenceGateChecks, actions, runner = 'ubuntu-latest' }: GateOptions): WorkflowObject => ({
  name: 'evidence-presign-notice',
  'runs-on': runner,
  'timeout-minutes': 3,
  'continue-on-error': true,
  needs: evidenceGateChecks.map((check) => `evidence-gate-${check}`),
  if: "always() && github.event_name == 'pull_request'",
  permissions: { contents: 'read', 'pull-requests': 'read' },
  steps: [
    { uses: actions.checkout, with: { 'persist-credentials': false } },
    {
      name: 'Say which checks a pre-signed note would have covered',
      env: {
        LINES: evidenceGateChecks.map((check) => `\${{ needs.evidence-gate-${check}.outputs.line }}`).join('\n'),
        BASE_SHA: '${{ github.event.pull_request.base.sha }}',
        REPOSITORY: '${{ github.repository }}',
        PR_NUMBER: '${{ github.event.pull_request.number }}',
        GH_TOKEN: '${{ github.token }}',
      },
      run: `git fetch --no-tags --depth=1 -q origin "$BASE_SHA" && git show "$BASE_SHA:scripts/ci-evidence-presign-notice" > "$RUNNER_TEMP/ci-evidence-presign-notice" && python3 "$RUNNER_TEMP/ci-evidence-presign-notice" || echo 'evidence-presign-notice: not at the base yet, or it could not run; nothing to say'`,
    },
  ],
})
export const evidenceSourceJob = (producer: string, actions: Actions): WorkflowObject => ({
      name: 'evidence-source',
      'runs-on': 'ubuntu-latest',
      'timeout-minutes': 5,
      'continue-on-error': true,
      permissions: { contents: 'read' },
      steps: [
        { uses: actions.checkout, with: { 'persist-credentials': false } },
        {
          name: 'Retain effective tested source',
          // Execute the workflow's embedded producer outside the checkout. It observes Git
          // objects only; it never executes source or carries a production signing key.
          run: `cat > "$RUNNER_TEMP/ci-evidence-source-producer.py" <<'EVIDENCE_SOURCE_PY'\n${producer.trimEnd()}\nEVIDENCE_SOURCE_PY\npython3 "$RUNNER_TEMP/ci-evidence-source-producer.py"`,
        },
        {
          name: 'Upload effective tested source',
          uses: actions.uploadArtifact,
          with: {
            name: 'ci-evidence-source-${{ github.run_attempt }}',
            path: '${{ runner.temp }}/ci-evidence-source/',
            'if-no-files-found': 'error',
            'retention-days': 14,
          },
        },
      ],
    })
export interface SigningOptions {
  readonly actions: Actions
  readonly checkoutSteps: readonly WorkflowObject[]
  readonly environment: string
  readonly needs: readonly string[]
  readonly stageNames: readonly string[]
  readonly stepNames: readonly string[]
  readonly laneNames: readonly string[]
  readonly webNoteEnv: WorkflowObject
  readonly configDir?: string
  readonly legacyConfigDir?: string
}
const signingEvent = "(github.event_name == 'merge_group' || (github.event_name == 'push' && github.ref == 'refs/heads/main') || (github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'))"

export const evidenceAggregateSigningJob = ({ actions, checkoutSteps, environment, needs, stageNames, stepNames, laneNames, webNoteEnv, configDir = '.fractal', legacyConfigDir = '.st' }: SigningOptions): WorkflowObject => ({
      name: 'evidence-note-linux-gate',
      // The fractal-web jobs and gate are for the web lane's own whole-check note; the linux-gate note leaves them out.
      needs,
      // The merge queue, main and pull requests from this repository sign; a fork never gets the key.
      if: "${{ always() && (github.event_name == 'merge_group' || (github.event_name == 'push' && github.ref == 'refs/heads/main') || (github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main') || (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository)) }}",
      'runs-on': 'ubuntu-latest',
      environment,
      permissions: { contents: 'write' },
      'timeout-minutes': 15,
      defaults: { run: { shell: 'bash' } },
      env: {
        EVIDENCE_PUSH_TOKEN: '${{ github.token }}',
        PR_HEAD_REPOSITORY: '${{ github.event.pull_request.head.repo.full_name }}',
        PR_BASE_SHA: '${{ github.event.pull_request.base.sha }}',
        PR_HEAD_SHA: '${{ github.event.pull_request.head.sha }}',
        PR_USER: '${{ github.event.pull_request.user.login }}',
        NEEDS_JSON: '${{ toJSON(needs) }}',
      },
      steps: [
        // The tested commit with its whole history: a note's parent is that commit, and the server
        // refuses a push from a shallow repository.
        ...checkoutSteps,
        {
          name: 'Take the signer scripts from the base commit',
          id: 'base',
          'continue-on-error': true,
          env: { BASE_SHA: '${{ github.event.merge_group.base_sha || github.event.pull_request.base.sha || github.sha }}' },
          run: `rm -rf "$RUNNER_TEMP/evidence-base" && mkdir "$RUNNER_TEMP/evidence-base"
git cat-file -e "$BASE_SHA^{commit}" 2>/dev/null || git fetch --quiet origin "$BASE_SHA"
git archive "$BASE_SHA" scripts | tar -x -C "$RUNNER_TEMP/evidence-base"`,
        },
        { name: 'May this job use the signing key?', id: 'guard', 'continue-on-error': true, run: 'python3 "$RUNNER_TEMP/evidence-base/scripts/ci-evidence-signing" guard' },
        {
          name: 'Write the signer configuration and key',
          id: 'configure',
          if: "${{ steps.guard.outcome == 'success' }}",
          'continue-on-error': true,
          env: { EVIDENCE_SIGNING_KEY: '${{ secrets.EVIDENCE_SIGNING_KEY }}' },
          run: `set -o pipefail
python3 "$RUNNER_TEMP/evidence-base/scripts/ci-evidence-signing" configure | tee "$RUNNER_TEMP/evidence-signer-home"`,
        },
        {
          name: 'Sign the linux-gate note',
          id: 'sign',
          if: "${{ steps.configure.outcome == 'success' }}",
          'continue-on-error': true,
          run: `helper="$RUNNER_TEMP/evidence-base/scripts/ci-evidence-signing"
python3 "$helper" once linux-gate
python3 "$helper" aggregate "$RUNNER_TEMP/gate-facts.json"
home=$(tail -n 1 "$RUNNER_TEMP/evidence-signer-home")
HOME="$home" python3 "$RUNNER_TEMP/evidence-base/scripts/evidence-wrap" --check linux-gate \\
  --aggregate "$RUNNER_TEMP/gate-facts.json" --attempt "$GITHUB_RUN_ATTEMPT" \\
  --change-id "github:$GITHUB_REPOSITORY@$GITHUB_SHA" --toolchain-sha256 "$(printf 'github-hosted|%s' "\${ImageVersion:-unknown}" | sha256sum | cut -d' ' -f1)" \\
  --signer '["python3","'"$RUNNER_TEMP"'/evidence-base/scripts/evidence-sign"]' --out "$RUNNER_TEMP/evidence-notes/gate"`,
        },
        // The fractal-web check's one whole-check note, from the lane's jobs in this run: refused when the lane did not run,
        // when any execution shard was skipped, failed or was cancelled, or when its evidence gate skipped it. Signed here
        // because this job, not the always-run fractal-web job, holds the key; independent of the linux-gate note above.
        {
          name: 'Sign the fractal-web note',
          id: 'sign-fractal-web',
          if: "${{ steps.configure.outcome == 'success' }}",
          'continue-on-error': true,
          env: webNoteEnv,
          // A base whose helper predates the whole-check note would sign the linux-gate shape under this name: skip it.
          run: `helper="$RUNNER_TEMP/evidence-base/scripts/ci-evidence-signing"
grep -q fractal_web_aggregate "$helper" || { echo "no fractal-web aggregate in the base commit's signing helper; not signed"; exit 1; }
python3 "$helper" once fractal-web
python3 "$helper" aggregate "$RUNNER_TEMP/fractal-web-facts.json"
home=$(tail -n 1 "$RUNNER_TEMP/evidence-signer-home")
HOME="$home" python3 "$RUNNER_TEMP/evidence-base/scripts/evidence-wrap" --check fractal-web \\
  --aggregate "$RUNNER_TEMP/fractal-web-facts.json" --attempt "$GITHUB_RUN_ATTEMPT" \\
  --change-id "github:$GITHUB_REPOSITORY@$GITHUB_SHA" --toolchain-sha256 "$(printf 'github-hosted|%s' "\${ImageVersion:-unknown}" | sha256sum | cut -d' ' -f1)" \\
  --signer '["python3","'"$RUNNER_TEMP"'/evidence-base/scripts/evidence-sign"]' --out "$RUNNER_TEMP/evidence-notes/fractal-web"`,
        },
        // The stage jobs' signed notes, written as packs by each stage's own signing steps. Collected and published
        // whenever the key is configured, whether or not the aggregate signed: a stage note stands on its own (its
        // producer refuses when its own gate skipped, and only notes that verify are published), and an aggregate
        // that refused simply leaves no linux-gate note among them.
        {
          name: 'Collect the stage notes',
          if: "${{ steps.configure.outcome == 'success' }}",
          'continue-on-error': true,
          uses: actions.downloadArtifact,
          with: { pattern: 'evidence-note-*', path: '${{ runner.temp }}/evidence-notes/stages', 'merge-multiple': true },
        },
        {
          name: 'Publish the notes that verify',
          if: "${{ steps.configure.outcome == 'success' }}",
          'continue-on-error': true,
          env: { BASE_SHA: '${{ github.event.merge_group.base_sha || github.event.pull_request.base.sha || github.sha }}' },
          run: `# arn:lmig:smalltalk:2026-10-27-dot-fractal-config: fall back only on absence at this base.
key_entry=$(git ls-tree --full-tree "$BASE_SHA" -- ${configDir}/evidence-keys) || exit 1
key_path=${legacyConfigDir}/evidence-keys
if [ -n "$key_entry" ]; then key_path=${configDir}/evidence-keys; fi
git show "$BASE_SHA:$key_path" > "$RUNNER_TEMP/evidence-keys" || { echo "::warning::cannot read evidence keys at the base commit; nothing is published"; exit 1; }
python3 "$RUNNER_TEMP/evidence-base/scripts/evidence-publish" --notes "$RUNNER_TEMP/evidence-notes" \\
  --keys "$RUNNER_TEMP/evidence-keys" --checks "linux-gate,${[...stageNames, ...stepNames, ...laneNames].join(',')}" --remote origin | tee "$RUNNER_TEMP/evidence-publish.json"`,
        },
        // Shadow verification: what would a gate that fetched these refs from the remote say about each lane? Reported
        // in the job summary only; it gates nothing, runs from the BASE commit's scripts (absent there: skipped), and
        // is fail-soft like every other step of this job.
        {
          name: 'Shadow-verify the published notes',
          if: "${{ always() && steps.configure.outcome == 'success' }}",
          'continue-on-error': true,
          run: `shadow="$RUNNER_TEMP/evidence-base/scripts/ci-evidence-shadow"
[ -f "$shadow" ] || { echo "no ci-evidence-shadow at the base commit; skipped"; exit 0; }
python3 "$shadow" --publish-result "$RUNNER_TEMP/evidence-publish.json" --keys "$RUNNER_TEMP/evidence-keys" \\
  --verifier "$RUNNER_TEMP/evidence-base/scripts/evidence-verify" --checks "linux-gate,${[...stageNames, ...stepNames, ...laneNames].join(',')}" --optional "${laneNames.join(',')}" --remote origin`,
        },
        { name: 'Remove the key', if: 'always()', 'continue-on-error': true, run: 'python3 "$RUNNER_TEMP/evidence-base/scripts/ci-evidence-signing" cleanup' },
      ],
    })
export const evidenceRustTestSigningJob = ({ actions, checkoutSteps, environment, needs, stageNames, stepNames, laneNames, webNoteEnv, configDir = '.fractal', legacyConfigDir = '.st' }: SigningOptions): WorkflowObject => ({
      name: 'evidence-note-rust-tests',
      needs,
      if: `\${{ !cancelled() && ${signingEvent} }}`,
      'runs-on': 'ubuntu-latest',
      environment,
      permissions: { contents: 'write' },
      'timeout-minutes': 20,
      defaults: { run: { shell: 'bash' } },
      env: {
        EVIDENCE_PUSH_TOKEN: '${{ github.token }}',
        NEEDS_JSON: '${{ toJSON(needs) }}',
        BASE_SHA: '${{ github.event.merge_group.base_sha || github.sha }}',
      },
      steps: [
        // The tested commit with its whole history: a note's parent is that commit, and the server refuses a push from a shallow repository.
        ...checkoutSteps,
        {
          name: 'Take the signer scripts from the base commit',
          id: 'base',
          'continue-on-error': true,
          run: `rm -rf "$RUNNER_TEMP/evidence-base" && mkdir "$RUNNER_TEMP/evidence-base"
git cat-file -e "$BASE_SHA^{commit}" 2>/dev/null || git fetch --quiet origin "$BASE_SHA"
git archive "$BASE_SHA" scripts | tar -x -C "$RUNNER_TEMP/evidence-base"`,
        },
        {
          name: 'Collect the test shards\' JUnit reports',
          if: "${{ steps.base.outcome == 'success' }}",
          'continue-on-error': true,
          uses: actions.downloadArtifact,
          with: { pattern: 'rust-test-junit-*', path: '${{ runner.temp }}/rust-test-junit' },
        },
        {
          name: 'Decide which crates may be signed',
          id: 'plan',
          if: "${{ steps.base.outcome == 'success' }}",
          'continue-on-error': true,
          run: `[ -f "$RUNNER_TEMP/evidence-base/scripts/ci-rust-test-notes" ] || { echo "no ci-rust-test-notes at the base commit; nothing is signed"; exit 1; }
python3 "$RUNNER_TEMP/evidence-base/scripts/ci-rust-test-notes" plan --reports "$RUNNER_TEMP/rust-test-junit" --out "$RUNNER_TEMP/rust-test-plan"`,
        },
        {
          name: 'May this job use the signing key?',
          id: 'guard',
          if: "${{ steps.plan.outcome == 'success' }}",
          'continue-on-error': true,
          run: `python3 "$RUNNER_TEMP/evidence-base/scripts/ci-evidence-signing" guard
python3 "$RUNNER_TEMP/evidence-base/scripts/ci-rust-test-notes" guard`,
        },
        {
          name: 'Write the signer configuration and key',
          id: 'configure',
          if: "${{ steps.guard.outcome == 'success' }}",
          'continue-on-error': true,
          env: { EVIDENCE_SIGNING_KEY: '${{ secrets.EVIDENCE_SIGNING_KEY }}' },
          run: `set -o pipefail
python3 "$RUNNER_TEMP/evidence-base/scripts/ci-evidence-signing" configure | tee "$RUNNER_TEMP/evidence-signer-home"`,
        },
        {
          name: 'Sign the per-crate rust-tests notes',
          id: 'sign',
          if: "${{ steps.configure.outcome == 'success' }}",
          'continue-on-error': true,
          run: `python3 "$RUNNER_TEMP/evidence-base/scripts/ci-evidence-signing" once rust-tests
home=$(tail -n 1 "$RUNNER_TEMP/evidence-signer-home")
HOME="$home" python3 "$RUNNER_TEMP/evidence-base/scripts/ci-rust-test-notes" sign --plan "$RUNNER_TEMP/rust-test-plan" --out "$RUNNER_TEMP/rust-test-notes"`,
        },
        // Whatever was signed is published, even when some crate's signature failed: each record stands on its own.
        {
          name: 'Publish the notes that verify',
          if: "${{ steps.configure.outcome == 'success' }}",
          'continue-on-error': true,
          run: `[ -d "$RUNNER_TEMP/rust-test-notes" ] || { echo "nothing was signed"; exit 0; }
# arn:lmig:smalltalk:2026-10-27-dot-fractal-config: fall back only on absence at this base.
key_entry=$(git ls-tree --full-tree "$BASE_SHA" -- ${configDir}/evidence-keys) || exit 1
key_path=${legacyConfigDir}/evidence-keys
if [ -n "$key_entry" ]; then key_path=${configDir}/evidence-keys; fi
git show "$BASE_SHA:$key_path" > "$RUNNER_TEMP/evidence-keys" || { echo "::warning::cannot read evidence keys at the base commit; nothing is published"; exit 1; }
python3 "$RUNNER_TEMP/evidence-base/scripts/evidence-publish" --notes "$RUNNER_TEMP/rust-test-notes" --keys "$RUNNER_TEMP/evidence-keys" \\
  --checks rust-tests --limit 400 --remote origin`,
        },
        { name: 'Remove the key', if: 'always()', 'continue-on-error': true, run: 'python3 "$RUNNER_TEMP/evidence-base/scripts/ci-evidence-signing" cleanup' },
      ],
    })
export const evidenceObserveJob = (runnerLabels: readonly string[], actions: Actions): WorkflowObject => ({
      name: 'observe',
      // Merge-group runs of this repository only; a manual replay only from main. No pull
      // request event, fork or branch workflow can reach the observer or its credentials.
      if: "${{ (github.event_name == 'workflow_run' && github.event.workflow_run.event == 'merge_group' && github.event.workflow_run.conclusion != 'cancelled' && github.event.workflow_run.head_repository.full_name == github.repository) || (github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main') }}",
      'runs-on': runnerLabels,
      'timeout-minutes': 30,
      defaults: { run: { shell: 'bash' } },
      steps: [
        // The default branch's checkout supplies this script and the accepted key list.
        { uses: actions.checkout, with: { ref: 'main', 'persist-credentials': false } },
        {
          name: 'Record the finished run as evidence',
          env: {
            GH_TOKEN: '${{ github.token }}',
            EVIDENCE_PUSH_TOKEN: '${{ github.token }}',
            OBSERVED_RUN: '${{ github.event.workflow_run.id || inputs.run_id }}',
            OBSERVED_ATTEMPT: '${{ github.event.workflow_run.run_attempt || inputs.attempt }}',
          },
          run: `python3 scripts/ci-evidence-observe --repository "$GITHUB_REPOSITORY" --run "$OBSERVED_RUN" --attempt "$OBSERVED_ATTEMPT" \\
  --keys-from HEAD --scratch "$HOME/.cache/evidence-observe/scratch" --remote "https://github.com/$GITHUB_REPOSITORY.git"`,
        },
      ],
    })
export const signedTreeJob = (actions: Actions): WorkflowObject => ({
      name: 'signed-tree',
      'runs-on': 'ubuntu-latest',
      'timeout-minutes': 5,
      'continue-on-error': true,
      defaults: { run: { shell: 'bash' } },
      steps: [
        // No ref: for pull_request_target this is the base branch tip, never the pull request.
        { uses: actions.checkout, with: { 'persist-credentials': false } },
        {
          name: 'Would this pull request be rejected for lacking a signed note?',
          env: {
            REPOSITORY: '${{ github.repository }}',
            PR_NUMBER: '${{ github.event.pull_request.number }}',
            PR_HEAD_SHA: '${{ github.event.pull_request.head.sha }}',
            PR_HEAD_REPOSITORY: '${{ github.event.pull_request.head.repo.full_name }}',
            PR_DRAFT: '${{ github.event.pull_request.draft }}',
          },
          run: 'python3 scripts/ci-signed-tree',
        },
      ],
    })
