import { spawnSync } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const directory = resolve(process.argv[2] ?? 'tmp/buck2-evidence')
mkdirSync(directory, { recursive: true })
const buck = process.env.BUCK2_BIN ?? 'buck2'
const run = (command: string[]): string => {
  console.log(`$ ${command.join(' ')}`)
  const result = spawnSync(command[0]!, command.slice(1), { encoding: 'utf8', maxBuffer: 128 * 1024 * 1024 })
  process.stdout.write(result.stdout ?? '')
  process.stderr.write(result.stderr ?? '')
  console.log(`EXIT_CODE=${result.status}`)
  if (result.error !== undefined) throw result.error
  if (result.status !== 0) process.exit(result.status ?? 1)
  return `${result.stdout}\n${result.stderr}`
}
const metadataResult = spawnSync('cargo', ['metadata', '--locked', '--no-deps', '--format-version=1'], { encoding: 'utf8' })
if (metadataResult.status !== 0) throw new Error(metadataResult.stderr)
const metadata = JSON.parse(metadataResult.stdout)
const expectedLabels: string[] = []
const cargo: string[] = []
const buckTests: string[] = []
const names = (output: string): string[] => output
  .replaceAll(/\x1b\[[0-9;]*m/g, '')
  .replaceAll(/^\[\d{4}-[^\]]+\]\s?/gm, '')
  .split('\n').filter((line) => line.endsWith(': test')).map((line) => line.slice(0, -6))
for (const pkg of metadata.packages.filter((pkg: { id: string }) => metadata.workspace_members.includes(pkg.id))) {
  const member = pkg.manifest_path.slice(metadata.workspace_root.length + 1, -'/Cargo.toml'.length)
  for (const target of pkg.targets) {
    if (!target.test) continue
    let harness: string
    let selector: string[]
    if (target.kind.includes('lib') || target.kind.includes('proc-macro')) {
      harness = 'unit-lib'
      selector = ['--lib']
    } else if (target.kind.includes('bin')) {
      harness = `unit-bin-${target.name}`
      selector = ['--bin', target.name]
    } else if (target.kind.includes('test')) {
      harness = `integration-${target.name}`
      selector = ['--test', target.name]
    } else {
      throw new Error(`Unsupported Cargo test target: ${pkg.name}/${target.name}/${target.kind}`)
    }
    const label = `//${member}:${harness}`
    expectedLabels.push(label)
    const key = `${pkg.name}|${harness}|`
    cargo.push(...names(run(['cargo', 'test', '--locked', '--package', pkg.name, ...selector, '--', '--list'])).map((name) => key + name))
    buckTests.push(...names(run([buck, 'test', '--test-executor-stdout=-', '--test-executor-stderr=-', label, '--', '--test-arg=--list'])).map((name) => key + name))
  }
  // Shared projector explicitly does not support doctests: any real doctest must fail parity.
  if (pkg.targets.some((target: { doctest: boolean }) => target.doctest)) {
    cargo.push(...names(run(['cargo', 'test', '--locked', '--package', pkg.name, '--doc', '--', '--list'])).map((name) => `${pkg.name}|doctest|${name}`))
  }
}
const query = spawnSync(buck, ['uquery', 'kind(".*rust_test", //crates/...)'], { encoding: 'utf8' })
if (query.status !== 0) throw new Error(query.stderr)
const actualLabels = query.stdout.trim().split('\n').filter(Boolean).map((label) => label.slice(label.indexOf('//'))).sort()
expectedLabels.sort()
writeFileSync(`${directory}/cargo-harnesses.txt`, `${expectedLabels.join('\n')}\n`)
writeFileSync(`${directory}/buck-harnesses.txt`, `${actualLabels.join('\n')}\n`)
for (const [name, inventory] of [['cargo', cargo], ['buck', buckTests]] as const) {
  inventory.sort()
  writeFileSync(`${directory}/${name}-tests.txt`, `${inventory.join('\n')}\n`)
  console.log(`${name.toUpperCase()} INVENTORY (${inventory.length})\n${inventory.join('\n')}`)
}
const diff = spawnSync('diff', ['-u', `${directory}/cargo-tests.txt`, `${directory}/buck-tests.txt`], { encoding: 'utf8' })
writeFileSync(`${directory}/parity.diff`, diff.stdout ?? '')
process.stdout.write(diff.stdout ?? '')
if (diff.status !== 0 || cargo.length === 0 || expectedLabels.join('\n') !== actualLabels.join('\n')) {
  throw new Error(`Cargo/Buck parity failed: Cargo=${cargo.length}, Buck=${buckTests.length}; harnesses Cargo=${expectedLabels.length}, Buck=${actualLabels.length}`)
}
console.log(`PARITY: ${cargo.length} tests, ${expectedLabels.length} harnesses; identical names and multiplicities, including ignored tests`)
