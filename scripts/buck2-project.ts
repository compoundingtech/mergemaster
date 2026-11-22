import { chmod } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { cargoProjection, members } from '../genie/buck2.ts'
import { cargoResourcesFor, rootResourcePaths } from '../genie/buck2-resources.ts'

// Cross-package files must be exported by their actual owner (the root BUCK).
const exportsPath = 'buck2/resource-exports.bzl'
const resourceExports = [
  '# @generated from genie/buck2-resources.json by scripts/buck2-project.ts.',
  '# Do not edit. Regenerate with scripts/buck2-prepare.',
  'load("@prelude//:prelude.bzl", "native")',
  '',
  'def export_cargo_resources():',
  ...rootResourcePaths.flatMap((path) => [
    '    native.export_file(',
    `        name = ${JSON.stringify(`cargo-resource/${path}`)},`,
    `        src = ${JSON.stringify(path)},`,
    '        visibility = ["PUBLIC"],',
    '    )',
  ]),
  '',
].join('\n')
if (await Bun.file(exportsPath).exists()) await chmod(exportsPath, 0o644)
await Bun.write(exportsPath, resourceExports)
await chmod(exportsPath, 0o444)

for (const member of members) {
  const output = cargoProjection({
    sourceUrl: pathToFileURL(resolve(member, 'BUCK.genie.ts')).href,
    ...cargoResourcesFor(member),
  })
  const destination = `${member}/BUCK`
  if (await Bun.file(destination).exists()) await chmod(destination, 0o644)
  await Bun.write(destination, output.stringify({ cwd: process.cwd(), location: resolve(member) }))
  await chmod(destination, 0o444)
}
