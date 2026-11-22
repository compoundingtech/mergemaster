import { pathToFileURL } from 'node:url'

const provider = process.env.MERGEMASTER_EFFECT_UTILS
if (provider === undefined) throw new Error('Run inside nix develop .#buck2-evidence')
// The flake selects the module's immutable store path at shell activation time.
const { defineCargoBuck2PackageProjection } = await import(pathToFileURL(`${provider}/rust/buck2-tools/core/cargo-buck2-package-projection.ts`).href)
const manifest = Bun.TOML.parse(await Bun.file(new URL('../Cargo.toml', import.meta.url)).text())
// All members opt in: discovery of new harnesses remains the shared projector's job.
export const members: string[] = manifest.workspace.members
export const cargoProjection = defineCargoBuck2PackageProjection({
  repoName: 'mergemaster',
  repoImportMetaUrl: import.meta.url,
  workspaceRoot: '.',
  workspaceMemberManifestPaths: members.map((member) => `${member}/Cargo.toml`),
  testPackagePaths: members,
  thirdPartyBuckPath: 'buck2/dependencies/BUCK',
  thirdPartyPackage: '//buck2/dependencies',
  buck2LoadLabelPrefix: '@rules//buck2',
  generatorSourcePaths: [
    'genie/buck2.ts', 'genie/buck2-resources.ts', 'genie/buck2-resources.json',
    'scripts/buck2-project.ts', 'flake.lock',
  ],
  regenerationCommand: 'nix develop .#buck2-evidence -c bash scripts/buck2-prepare',
})
