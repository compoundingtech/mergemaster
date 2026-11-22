import inventory from './buck2-resources.json'

// Phase-one effect-utils #2761 API. Activate with its published product pin;
// baked env!("CARGO_MANIFEST_DIR") paths are deliberately not supported.
const packages: Readonly<Record<string, {
  readonly compileTimeResources: readonly string[]
  readonly runtimeResources: readonly string[]
}>> = inventory.packages

export const rootResourcePaths = [...new Set(Object.entries(packages).flatMap(([member, resources]) =>
  [...resources.compileTimeResources, ...resources.runtimeResources].filter((path) => !path.startsWith(`${member}/`)),
))].sort()

export const cargoResourcesFor = (member: string) => {
  const resources = packages[member]
  if (resources === undefined) throw new Error(`Missing explicit Cargo resource inventory for ${member}`)
  const declaration = (path: string) => path.startsWith(`${member}/`)
    ? { path }
    : { path, label: `//:cargo-resource/${path}`, destination: { kind: 'repository' as const, path } }
  return {
    compileTimeResources: resources.compileTimeResources.map(declaration),
    runtimeResources: resources.runtimeResources.map(declaration),
  }
}
