import assert from 'node:assert/strict'
import { test } from 'node:test'
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { AlchemyContext } from 'alchemy/AlchemyContext'
import { State } from 'alchemy/State'
import { PlatformServices } from 'alchemy/Util/PlatformServices'
import { Effect } from 'effect'
import { checkState, operatorState, resolveStateDirectory } from './state.mjs'

test('state location honors operator configuration, XDG, and HOME outside the checkout', async () => {
  const root = mkdtempSync(join(tmpdir(), 'mergemaster-state-location-'))
  try {
    const checkout = join(root, 'checkout')
    mkdirSync(checkout)
    const configured = join(root, 'operator-state')
    assert.equal(resolveStateDirectory({}, root, checkout), join(root, '.local/state/mergemaster/iac'))
    assert.equal(resolveStateDirectory({ XDG_STATE_HOME: root }, root, checkout), join(root, 'mergemaster/iac'))
    assert.equal(resolveStateDirectory({ MERGEMASTER_IAC_STATE_DIR: configured }, root, checkout), configured)
    assert.throws(() => resolveStateDirectory({ MERGEMASTER_IAC_STATE_DIR: checkout }, root, checkout), /outside/)
    const alias = join(root, 'checkout-alias')
    symlinkSync(checkout, alias)
    assert.throws(() => resolveStateDirectory({ MERGEMASTER_IAC_STATE_DIR: join(alias, 'state') }, root, checkout), /outside/)
    assert.throws(() => resolveStateDirectory({ MERGEMASTER_IAC_STATE_DIR: 'relative' }, root, checkout), /absolute/)
    mkdirSync(join(configured, 'state/fixture-stack'), { recursive: true, mode: 0o700 })
    const stacks = await Effect.runPromise(Effect.gen(function* () {
      const state = yield* yield* State
      return yield* state.listStacks()
    }).pipe(
      Effect.provide(operatorState(configured)),
      Effect.provideService(AlchemyContext, { dotAlchemy: checkout, dev: false, adopt: false }),
      Effect.provide(PlatformServices),
    ))
    assert.deepEqual(stacks, ['fixture-stack'])
  } finally { rmSync(root, { recursive: true }) }
})

test('state scan enforces modes, rejects symlinks and key material without printing it', () => {
  const directory = mkdtempSync(join(tmpdir(), 'mergemaster-state-scan-'))
  try {
    const file = join(directory, 'state.json')
    writeFileSync(file, '{"privateKeySecret":{"name":"MERGEMASTER_APP_PRIVATE_KEY"}}', { mode: 0o600 })
    checkState(directory) // Declared destination metadata is not private-key material.
    chmodSync(file, 0o644)
    assert.throws(() => checkState(directory), /0600/)
    chmodSync(file, 0o600)
    chmodSync(directory, 0o755)
    assert.throws(() => checkState(directory), /0700/)
    chmodSync(directory, 0o700)
    for (const contents of ['-----BEGIN RSA PRIVATE KEY-----fixture-secret', 'BEGIN EC PRIVATE KEY', '{"pem":"fixture-secret"}', '{"privateKey":"fixture-secret"}']) {
      writeFileSync(file, contents)
      assert.throws(() => checkState(directory), (error) => {
        assert.match(error.message, /Private-key marker/)
        assert.doesNotMatch(error.message, /fixture-secret/)
        return true
      })
    }
    writeFileSync(file, '{}')
    symlinkSync(file, join(directory, 'alias'))
    assert.throws(() => checkState(directory), /no symlinks/)
    assert.throws(() => checkState(join(directory, 'missing')), /ENOENT/)
  } finally { rmSync(directory, { recursive: true }) }
})

test('check-state command fails closed on a fixture without exposing key contents', () => {
  const directory = mkdtempSync(join(tmpdir(), 'mergemaster-check-state-cli-'))
  try {
    const file = join(directory, 'state.json')
    writeFileSync(file, '{}', { mode: 0o600 })
    const args = [fileURLToPath(new URL('./state.mjs', import.meta.url))]
    const options = { env: { ...process.env, MERGEMASTER_IAC_STATE_DIR: directory }, encoding: 'utf8' }
    assert.equal(spawnSync(process.execPath, args, options).status, 0)
    writeFileSync(file, ['-----', 'BEGIN PRIVATE KEY-----fixture-secret'].join(''))
    const failed = spawnSync(process.execPath, args, options)
    assert.notEqual(failed.status, 0)
    assert.match(failed.stderr, /Private-key marker/)
    assert.doesNotMatch(failed.stdout + failed.stderr, /fixture-secret/)
  } finally { rmSync(directory, { recursive: true }) }
})
