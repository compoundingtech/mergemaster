import { cargoProjection } from '../../genie/buck2.ts'
import { cargoResourcesFor } from '../../genie/buck2-resources.ts'

export default cargoProjection({
  sourceUrl: import.meta.url,
  ...cargoResourcesFor('crates/mergemaster-evidence'),
})
