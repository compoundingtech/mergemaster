import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fromToken } from '@alchemy.run/github/Credentials'
import { Providers as BaseProviders } from '@alchemy.run/github/Providers'
import * as GitHub from '@overeng/alchemy-github'
import { AlchemyContext } from 'alchemy/AlchemyContext'
import * as Provider from 'alchemy/Provider'
import { State } from 'alchemy/State'
import { encodeState } from 'alchemy/State/StateEncoding'
import { scratchStack, toEffect } from 'alchemy/Test/Core'
import { Effect, Layer, Schema } from 'effect'
import { test } from 'node:test'
import { resources, publisherEnvironment, publisherPrivateKey } from './stack.ts'
import { checkState } from './state.mjs'

const encode = Schema.encodeSync(Schema.fromJsonString(Schema.Unknown))

test('env-sourced callback code never enters planned or created App state', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mergemaster-manifest-code-'))
  const code = 'callback-only-in-environment'
  const previousCode = process.env.APP_MANIFEST_CODE
  const previousState = process.env.APP_MANIFEST_CODE_STATE
  const pem = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' })
  const publicKey = Buffer.alloc(32)
  publicKey[0] = 9 // Curve25519 base point; no secret-key dependency is needed by this sink fixture.
  let conversions = 0
  let writes = 0
  const secretRoot = `/repos/schickling/factory/environments/${publisherEnvironment}/secrets`
  const metadata = { id: 123, slug: 'factory-evidence', owner: { login: 'schickling' },
    permissions: { checks: 'write', metadata: 'read' }, events: [] }
  const server = createServer((request, response) => {
    const path = (request.url ?? '').replace(/^\/api/, '')
    response.setHeader('content-type', 'application/json')
    if (request.method === 'GET' && path === `${secretRoot}/public-key`) {
      response.end(encode({ key: publicKey.toString('base64'), key_id: 'fixture-key' }))
    } else if (request.method === 'GET' && path === `${secretRoot}/${publisherPrivateKey}`) {
      response.statusCode = writes === 0 ? 404 : 200
      response.end(encode(writes === 0 ? { message: 'Not Found' } : {
        name: publisherPrivateKey, updated_at: '2026-10-31T00:00:00Z',
      }))
    } else if (request.method === 'POST' && path === `/app-manifests/${code}/conversions`) {
      conversions++
      response.statusCode = 201
      response.end(encode({ ...metadata, pem }))
    } else if (request.method === 'PUT' && path === `${secretRoot}/${publisherPrivateKey}`) {
      writes++
      response.statusCode = 201
      response.end('{}')
    } else if (request.method === 'GET' && path === '/apps/factory-evidence') {
      response.end(encode(metadata))
    } else {
      response.statusCode = 404
      response.end('{}')
    }
  })
  try {
    process.env.APP_MANIFEST_CODE = code
    delete process.env.APP_MANIFEST_CODE_STATE
    const listening = Promise.withResolvers<void>()
    server.once('error', listening.reject)
    server.listen(0, '127.0.0.1', listening.resolve)
    await listening.promise
    const address = server.address()
    assert.ok(address !== null && typeof address !== 'string')
    const environmentProvider = Provider.succeed(GitHub.Environment, {
      list: () => Effect.succeed([]), read: ({ output }) => Effect.succeed(output),
      diff: () => Effect.succeed(undefined), delete: () => Effect.die('No fixture deletion'),
      reconcile: () => Effect.succeed({ environmentId: 1, nodeId: 'fixture', name: publisherEnvironment,
        htmlUrl: 'https://example.invalid', createdAt: '', updatedAt: '' }),
    })
    const providers = Layer.merge(
      Layer.effect(GitHub.Providers, Provider.collection([GitHub.App])).pipe(
        Layer.provide(GitHub.AppProvider),
        Layer.provideMerge(GitHub.ManifestCodes.fromEnv('APP_MANIFEST_CODE')),
        Layer.provideMerge(fromToken('fixture-token', { baseUrl: `http://127.0.0.1:${address.port}/api` })),
      ),
      Layer.effect(BaseProviders, Provider.collection([GitHub.Environment])).pipe(Layer.provide(environmentProvider)),
    )
    const options = { providers, stage: 'test', dev: false, sidecar: false }
    const stack = scratchStack(options, 'RepositoryCheckPublishers')
    const persisted = Effect.gen(function* () {
      const store = yield* yield* State
      return yield* store.get({ stack: stack.name, stage: stack.stage, fqn: 'graph-publisher-app' })
    }).pipe(Effect.provide(stack.state))
    const pending = await Effect.runPromise(toEffect(Effect.gen(function* () {
      yield* stack.deploy(resources())
      return yield* persisted
    }), { ...options, state: stack.state }).pipe(
      Effect.provideService(AlchemyContext, { dotAlchemy: directory, dev: false, adopt: false }),
    ))
    assert.ok(pending?.kind !== 'action' && pending?.attr?.status === 'pending')
    process.env.APP_MANIFEST_CODE_STATE = pending.attr.state
    // Match two operator invocations: Alchemy snapshots the shell configuration per run.
    const rows = await Effect.runPromise(toEffect(Effect.gen(function* () {
      const program = resources({ graph: { state: process.env.APP_MANIFEST_CODE_STATE } })
      const plan = yield* stack.plan(program)
      const app = plan.resources['graph-publisher-app']
      assert.ok(app?.action === 'update')
      assert.deepEqual(app.props.conversion, { state: pending.attr.state })
      assert.ok(!encode(encodeState(app.props)).includes(code))
      assert.equal(conversions, 0)
      yield* stack.deploy(program)
      const registered = yield* persisted
      assert.ok(registered?.kind !== 'action' && registered?.attr?.status === 'registered')
      assert.deepEqual(registered.props.conversion, { state: pending.attr.state })
      return [pending, registered]
    }), { ...options, state: stack.state }).pipe(
      Effect.provideService(AlchemyContext, { dotAlchemy: directory, dev: false, adopt: false }),
    ))
    assert.equal(conversions, 1)
    assert.equal(writes, 1)
    const rowsDirectory = join(directory, 'persisted-rows')
    await mkdir(rowsDirectory, { mode: 0o700 })
    for (const [index, row] of rows.entries()) {
      const serialized = encode(encodeState(row))
      assert.ok(!serialized.includes(code))
      assert.doesNotMatch(serialized, /__redacted__|PRIVATE KEY/)
      await writeFile(join(rowsDirectory, `${index}.json`), serialized, { mode: 0o600 })
    }
    checkState(rowsDirectory)
  } finally {
    if (previousCode === undefined) delete process.env.APP_MANIFEST_CODE
    else process.env.APP_MANIFEST_CODE = previousCode
    if (previousState === undefined) delete process.env.APP_MANIFEST_CODE_STATE
    else process.env.APP_MANIFEST_CODE_STATE = previousState
    if (server.listening) {
      const closed = Promise.withResolvers<void>()
      server.close((error) => error ? closed.reject(error) : closed.resolve())
      await closed.promise
    }
    await rm(directory, { recursive: true })
  }
})
