import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { checkState, prepareStateDirectory } from './state.mjs'

const directory = prepareStateDirectory()
const result = spawnSync(process.execPath, [
  '--import', fileURLToPath(new URL('./register.mjs', import.meta.url)),
  fileURLToPath(new URL('./node_modules/alchemy/bin/cli.js', import.meta.url)),
  ...process.argv.slice(2),
], { stdio: 'inherit', env: { ...process.env, MERGEMASTER_IAC_STATE_DIR: directory } })
checkState(directory)
if (result.error) throw result.error
process.exitCode = result.status ?? 1
