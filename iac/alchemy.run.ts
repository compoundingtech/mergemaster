import * as Alchemy from 'alchemy'
import * as GitHub from '@overeng/alchemy-github'
import { resources } from './stack.ts'
import { operatorState, prepareStateDirectory } from './state.mjs'

export default Alchemy.Stack('RepositoryCheckPublishers', {
  providers: GitHub.providers({ manifestCodeSource: GitHub.ManifestCodes.fromEnv('APP_MANIFEST_CODE') }),
  state: operatorState(prepareStateDirectory()),
}, resources({ [process.env.APP_REPOSITORY ?? 'graph']: {
  state: process.env.APP_MANIFEST_CODE_STATE,
  adoptSlug: process.env.APP_ADOPT_SLUG,
} }))
