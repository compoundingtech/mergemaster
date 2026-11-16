import * as GitHub from '@overeng/alchemy-github'
import * as Output from 'alchemy/Output'
import { Effect } from 'effect'
import consumers from './consumers.json' with { type: 'json' }

/** The reconciler reads this same allowlist; consumers never receive the App key. */
export const repositories = consumers

export const publisherEnvironment = 'mergemaster-check-publisher'
export const publisherPrivateKey = 'MERGEMASTER_APP_PRIVATE_KEY'
export const publisher = {
  owner: 'schickling',
  name: 'Mergemaster Evidence',
  keyOwner: 'compoundingtech',
  keyRepository: 'mergemaster',
  defaultBranch: 'main',
} as const

/** Only these non-secret facts cross the stack output boundary. */
export const appOutput = (app: GitHub.AppAttributes) => app.status === 'pending'
  ? { status: app.status, manifestHtml: app.manifestHtml, state: app.state, expiresAt: app.expiresAt }
  : { status: app.status, integrationId: app.integrationId, slug: app.slug }

export interface Registration {
  readonly state?: string
}

export const resources = (registration: Registration = {}) => Effect.gen(function* () {
  const keyEnvironment = yield* GitHub.Environment('publisher-key-environment', {
    owner: publisher.keyOwner, repository: publisher.keyRepository, name: publisherEnvironment,
    deploymentBranchPolicy: { customBranchPolicies: [publisher.defaultBranch] },
  })
  const app = yield* GitHub.App('publisher-app', {
    owner: publisher.owner, ownerType: 'user',
    manifest: {
      name: publisher.name,
      url: `https://github.com/${publisher.keyOwner}/${publisher.keyRepository}`,
      redirectUrl: 'http://127.0.0.1:8787/github-app-callback',
      permissions: { checks: 'write', contents: 'read', pull_requests: 'read' }, events: [],
    },
    privateKeySecret: {
      owner: publisher.keyOwner, repository: publisher.keyRepository,
      environment: keyEnvironment.name, name: publisherPrivateKey,
    },
    ...(registration.state === undefined ? {} : { conversion: { state: registration.state } }),
  })
  return {
    publisher: Output.map(Output.of(app), appOutput),
    // App installation consent remains manual; the provider cannot observe it without a key.
    installation: Output.map(Output.of(app), (attributes) => attributes.status === 'pending'
      ? { status: 'pending-registration' as const }
      : {
        status: 'consent-required' as const,
        url: `https://github.com/apps/${attributes.slug}/installations/new`,
        owner: publisher.owner,
        repositories: repositories.map((repo) => repo.repository),
      }),
    consumers: Object.fromEntries(repositories.map(({ id, ...repository }) => [id, repository])),
  }
})
