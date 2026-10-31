import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { AlchemyContext } from 'alchemy/AlchemyContext'
import { localState } from 'alchemy/State/LocalState'
import { Effect, Layer } from 'effect'

export const resolveStateDirectory = (env = process.env, home = homedir(), checkout = fileURLToPath(new URL('..', import.meta.url))) => {
  const directory = env.MERGEMASTER_IAC_STATE_DIR || join(env.XDG_STATE_HOME || join(home, '.local/state'), 'mergemaster/iac')
  if (!isAbsolute(directory)) throw new Error('State directory must be absolute')
  let ancestor = directory
  while (!existsSync(ancestor)) ancestor = dirname(ancestor)
  const canonical = resolve(realpathSync(ancestor), relative(ancestor, directory))
  const inside = relative(realpathSync(checkout), canonical)
  if (inside === '' || (inside !== '..' && !inside.startsWith('../') && !isAbsolute(inside))) {
    throw new Error('State directory must be outside the repository checkout')
  }
  return canonical
}

/** Fail closed without printing state contents or silently repairing unsafe files. */
export const checkState = (directory) => {
  const stat = lstatSync(directory)
  const mode = stat.isDirectory() ? 0o700 : 0o600
  if ((!stat.isDirectory() && !stat.isFile()) || (stat.mode & 0o7777) !== mode) {
    throw new Error('State requires regular files 0600 and directories 0700; no symlinks')
  }
  if (stat.isDirectory()) {
    for (const name of readdirSync(directory)) checkState(join(directory, name))
  } else if (/-----BEGIN|BEGIN .*PRIVATE KEY|"(?:pem|privateKey|private_key)"\s*:/i.test(readFileSync(directory, 'utf8'))) {
    throw new Error('Private-key marker found in state; contents withheld')
  }
}

export const prepareStateDirectory = () => {
  process.umask(0o077)
  const directory = resolveStateDirectory()
  mkdirSync(directory, { recursive: true, mode: 0o700 })
  checkState(directory)
  return directory
}

// Scope the public directory context to state only; retain the CLI's other defaults.
export const operatorState = (directory) => localState().pipe(Layer.provide(
  Layer.effect(AlchemyContext, Effect.map(AlchemyContext, (context) => ({ ...context, dotAlchemy: directory }))),
))

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const directory = resolveStateDirectory()
  if (!lstatSync(directory).isDirectory()) throw new Error('State root must be a directory')
  checkState(directory)
}
