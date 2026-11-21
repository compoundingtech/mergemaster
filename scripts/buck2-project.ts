import { chmod } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { cargoProjection, members } from '../genie/buck2.ts'

for (const member of members) {
  // In-crate binary tables are explicit compiler inputs, not just Rust source globs.
  const compileTimeResources = []
  for await (const file of new Bun.Glob('src/**/*').scan({ cwd: member, onlyFiles: true })) {
    if (!file.endsWith('.rs')) compileTimeResources.push({ path: `${member}/${file}` })
  }
  compileTimeResources.sort((a, b) => a.path.localeCompare(b.path))
  const output = cargoProjection({
    sourceUrl: pathToFileURL(resolve(member, 'BUCK.genie.ts')).href,
    compileTimeResources,
  })
  const destination = `${member}/BUCK`
  if (await Bun.file(destination).exists()) await chmod(destination, 0o644)
  await Bun.write(destination, output.stringify({ cwd: process.cwd(), location: resolve(member) }))
  await chmod(destination, 0o444)
}
