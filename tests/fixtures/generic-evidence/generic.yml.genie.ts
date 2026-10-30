import { githubWorkflow } from '../../repos/effect-utils/genie/external.ts'
import { genericEvidenceRequiredJob } from '../../genie/generic-evidence.ts'

// Copy to .github/workflows/generic.yml.genie.ts in a consumer with effect-utils.
// The App-token step deliberately fails closed until PR C' configures the App.
export default githubWorkflow({
  name: 'Generic evidence example',
  on: {
    pull_request: { types: ['opened', 'synchronize', 'reopened'] },
    pull_request_target: { types: ['opened', 'synchronize', 'reopened', 'ready_for_review', 'labeled'] },
  },
  permissions: { contents: 'read' },
  jobs: {
    validate: {
      name: 'validate',
      if: "github.event_name == 'pull_request'",
      'runs-on': 'ubuntu-24.04',
      permissions: { contents: 'read' },
      steps: [
        { uses: 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262', with: {
          ref: '${{ github.event.pull_request.head.sha }}', 'persist-credentials': false,
        } },
        { run: 'cargo test --workspace --locked' },
      ],
    },
    'generic-evidence': genericEvidenceRequiredJob({
      check: 'graph-full-check',
      checkout: 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262',
    }),
  },
})
