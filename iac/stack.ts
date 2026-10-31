import * as GitHub from '@overeng/alchemy-github'
import * as Output from 'alchemy/Output'
import { Effect, Redacted } from 'effect'

/** One entry per repository; each owns a separate checks-only App and key sink. */
export const repositories = [{
  id: 'graph', owner: 'schickling', repository: 'factory', defaultBranch: 'main',
  appName: 'Factory Evidence',
}] as const

export const publisherEnvironment = 'mergemaster-check-publisher'
export const publisherPrivateKey = 'MERGEMASTER_APP_PRIVATE_KEY'

/** Only these non-secret facts cross the stack output boundary. */
export const appOutput = (app: GitHub.AppAttributes) => app.status === 'pending'
  ? { status: app.status, manifestHtml: app.manifestHtml, state: app.state, expiresAt: app.expiresAt }
  : { status: app.status, integrationId: app.integrationId, slug: app.slug }

export interface Registration {
  readonly code?: string
  readonly state?: string
  readonly adoptSlug?: string
}

export const resources = (registrations: Readonly<Record<string, Registration>> = {}) => Effect.gen(function* () {
  const outputs = []
  for (const repo of repositories) {
    const registration = registrations[repo.id] ?? {}
    const environment = yield* GitHub.Environment(`${repo.id}-publisher-environment`, {
      owner: repo.owner, repository: repo.repository, name: publisherEnvironment,
      deploymentBranchPolicy: { customBranchPolicies: [repo.defaultBranch] },
    })
    const app = yield* GitHub.App(`${repo.id}-publisher-app`, {
      owner: repo.owner, ownerType: 'user',
      manifest: {
        name: repo.appName,
        url: `https://github.com/${repo.owner}/${repo.repository}`,
        redirectUrl: 'http://127.0.0.1:8787/github-app-callback',
        permissions: { checks: 'write' }, events: [],
      },
      privateKeySecret: {
        owner: repo.owner, repository: repo.repository,
        environment: environment.name, name: publisherPrivateKey,
      },
      ...(registration.code === undefined ? {} : {
        conversion: { code: Redacted.make(registration.code), state: registration.state ?? '' },
      }),
      ...(registration.adoptSlug === undefined ? {} : { adopt: { slug: registration.adoptSlug } }),
    })
    outputs.push([repo.id, Output.map(Output.of(app), appOutput)] as const)
  }
  return Object.fromEntries(outputs)
})
