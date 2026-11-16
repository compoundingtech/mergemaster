import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import * as GitHub from '@overeng/alchemy-github'
import { Providers as BaseProviders } from '@alchemy.run/github/Providers'
import { AlchemyContext } from 'alchemy/AlchemyContext'
import * as Provider from 'alchemy/Provider'
import * as Output from 'alchemy/Output'
import { scratchStack, toEffect } from 'alchemy/Test/Core'
import { Effect, Layer, Schema } from 'effect'
import { appOutput, resources, publisher, repositories, publisherEnvironment, publisherPrivateKey } from './stack.ts'

const encode = Schema.encodeSync(Schema.fromJsonString(Schema.Unknown))
const forbidden = /-----BEGIN .*PRIVATE KEY-----|fixture-private-key|fixture-secret-value/
const noSecrets = (value: unknown) => assert.doesNotMatch(encode(value), forbidden)

test('offline Alchemy plan shares one evidence App with central-only key custody and an enrollment allowlist', async () => {
  // Real engine, offline providers: observation is absent, mutation is forbidden.
  const unexpected = () => Effect.die('Offline plan attempted provider mutation')
  const appProvider = Provider.succeed(GitHub.App, {
    list: () => Effect.succeed([]), read: () => Effect.succeed(undefined),
    diff: () => Effect.succeed(undefined), reconcile: unexpected, delete: unexpected,
  })
  const environmentProvider = Provider.succeed(GitHub.Environment, {
    list: () => Effect.succeed([]), read: () => Effect.succeed(undefined),
    diff: () => Effect.succeed(undefined), reconcile: unexpected, delete: unexpected,
  })
  const providers = Layer.merge(
    Layer.effect(GitHub.Providers, Provider.collection([GitHub.App])).pipe(Layer.provide(appProvider)),
    Layer.effect(BaseProviders, Provider.collection([GitHub.Environment])).pipe(Layer.provide(environmentProvider)),
  )
  const directory = await mkdtemp(join(tmpdir(), 'mergemaster-app-plan-'))
  try {
    const options = { providers, stage: 'production', dev: false, sidecar: false }
    const stack = scratchStack(options, 'RepositoryCheckPublishers')
    await Effect.runPromise(toEffect(Effect.gen(function* () {
      const plan = yield* stack.plan(resources({ state: 'publisher-callback-state' }))
      assert.deepEqual(Object.keys(plan.resources).sort(), [
        'publisher-app', 'publisher-key-environment',
      ])
      const environments = { 'publisher-key-environment': { name: publisherEnvironment } }
      const app = plan.resources['publisher-app']
      const keyEnvironment = plan.resources['publisher-key-environment']
      assert.ok(app?.action === 'create')
      assert.ok(keyEnvironment?.action === 'create')
      assert.deepEqual(app.props.conversion, { state: 'publisher-callback-state' })
      assert.deepEqual(app.props.manifest.permissions, {
        checks: 'write', contents: 'read', pull_requests: 'read',
      })
      assert.deepEqual(app.props.manifest.events, [])
      assert.equal(app.props.manifest.name, publisher.name)
      assert.equal(app.props.owner, publisher.owner)
      assert.equal(app.props.manifest.url, 'https://github.com/compoundingtech/mergemaster')
      const keySink = yield* Output.evaluate(app.props.privateKeySecret, environments)
        .pipe(Effect.provide(stack.state))
      assert.deepEqual(keySink, {
        owner: publisher.keyOwner, repository: publisher.keyRepository,
        environment: publisherEnvironment, name: publisherPrivateKey,
      })
      assert.equal(keyEnvironment.props.owner, publisher.keyOwner)
      assert.equal(keyEnvironment.props.repository, publisher.keyRepository)
      assert.deepEqual(keyEnvironment.props.deploymentBranchPolicy, { customBranchPolicies: ['main'] })
      assert.deepEqual(repositories, [
        { id: 'graph', owner: 'schickling', repository: 'factory', repositoryId: 1398595057, defaultBranch: 'main' },
        { id: 'ptg', owner: 'schickling', repository: 'ptg', repositoryId: 1459778656, defaultBranch: 'main' },
      ])
      noSecrets(Object.values(plan.resources).map((resource) => resource.props))
      for (const attributes of [
        { status: 'registered', integrationId: 123, slug: 'mergemaster-evidence' },
        { status: 'pending', manifestHtml: '<form></form>', state: 'callback-state', expiresAt: 123 },
      ]) {
        const output = yield* Output.evaluate(plan.output, {
          ...environments,
          'publisher-app': { ...attributes, pem: 'fixture-private-key', value: 'fixture-secret-value' },
        }).pipe(Effect.provide(stack.state))
        assert.deepEqual(output, {
          publisher: attributes,
          installation: attributes.status === 'pending'
            ? { status: 'pending-registration' }
            : {
              status: 'consent-required',
              url: 'https://github.com/apps/mergemaster-evidence/installations/new',
              owner: publisher.owner, repositories: ['factory', 'ptg'],
            },
          consumers: Object.fromEntries(repositories.map(({ id, ...repository }) => [id, repository])),
        })
        noSecrets(output)
      }
    }), { ...options, state: stack.state }).pipe(
      Effect.provideService(AlchemyContext, { dotAlchemy: directory, dev: false, adopt: false }),
    ))
  } finally {
    await rm(directory, { recursive: true })
  }
})

test('registered stack outputs explicitly exclude even unexpected secret attributes', () => {
  const output = appOutput({
    status: 'registered', appId: 123, integrationId: 123, slug: 'mergemaster-evidence',
    permissions: { checks: 'write', contents: 'read', pull_requests: 'read' }, events: [],
    privateKeySecret: { owner: publisher.keyOwner, repository: publisher.keyRepository, name: publisherPrivateKey,
      environment: publisherEnvironment, scope: 'environment', updatedAt: '2026-10-31T00:00:00Z' },
    ...{ pem: '-----BEGIN PRIVATE KEY-----fixture-private-key', value: 'fixture-secret-value' },
  })
  assert.deepEqual(output, { status: 'registered', integrationId: 123, slug: 'mergemaster-evidence' })
  noSecrets(output)
})
