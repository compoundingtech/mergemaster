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
import { appOutput, resources, publisherEnvironment, publisherPrivateKey } from './stack.ts'

const encode = Schema.encodeSync(Schema.fromJsonString(Schema.Unknown))
const forbidden = /-----BEGIN .*PRIVATE KEY-----|fixture-private-key|fixture-secret-value/
const noSecrets = (value: unknown) => assert.doesNotMatch(encode(value), forbidden)

test('offline Alchemy plan declares a main-only environment and a sink-only checks App', async () => {
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
      const plan = yield* stack.plan(resources())
      assert.deepEqual(Object.keys(plan.resources).sort(), ['graph-publisher-app', 'graph-publisher-environment'])
      const app = plan.resources['graph-publisher-app']
      const environment = plan.resources['graph-publisher-environment']
      assert.ok(app?.action === 'create')
      assert.ok(environment?.action === 'create')
      noSecrets({ app: app.props, environment: environment.props })
      for (const attributes of [
        { status: 'registered', integrationId: 123, slug: 'graph-evidence' },
        { status: 'pending', manifestHtml: '<form></form>', state: 'callback-state', expiresAt: 123 },
      ]) {
        const output = yield* Output.evaluate(plan.output, {
          'graph-publisher-app': { ...attributes, pem: 'fixture-private-key', value: 'fixture-secret-value' },
        }).pipe(Effect.provide(stack.state))
        assert.deepEqual(output, { graph: attributes })
        noSecrets(output)
      }
      assert.deepEqual(environment.props.deploymentBranchPolicy, { customBranchPolicies: ['main'] })
      assert.deepEqual(app.props.manifest.permissions, { checks: 'write' })
      assert.deepEqual(app.props.manifest.events, [])
      assert.equal(app.props.privateKeySecret.name, publisherPrivateKey)
      assert.equal(app.props.privateKeySecret.owner, 'schickling')
      assert.equal(app.props.privateKeySecret.repository, 'smalltalk-graph')
      assert.equal(environment.props.name, publisherEnvironment)
      assert.equal('value' in app.props.privateKeySecret, false)
    }), { ...options, state: stack.state }).pipe(
      Effect.provideService(AlchemyContext, { dotAlchemy: directory, dev: false, adopt: false }),
    ))
  } finally {
    await rm(directory, { recursive: true })
  }
})

test('registered stack outputs explicitly exclude even unexpected secret attributes', () => {
  const output = appOutput({
    status: 'registered', appId: 123, integrationId: 123, slug: 'graph-evidence',
    permissions: { checks: 'write' }, events: [],
    privateKeySecret: { owner: 'schickling', repository: 'smalltalk-graph', name: publisherPrivateKey,
      environment: publisherEnvironment, scope: 'environment', updatedAt: '2026-10-31T00:00:00Z' },
    ...{ pem: '-----BEGIN PRIVATE KEY-----fixture-private-key', value: 'fixture-secret-value' },
  })
  assert.deepEqual(output, { status: 'registered', integrationId: 123, slug: 'graph-evidence' })
  noSecrets(output)
})
