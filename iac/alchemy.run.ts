import * as Alchemy from 'alchemy'
import * as GitHub from '@overeng/alchemy-github'
import { resources } from './stack.ts'
import { operatorState, prepareStateDirectory } from './state.mjs'

export default Alchemy.Stack('RepositoryCheckPublishers', {
  providers: GitHub.providers(),
  state: operatorState(prepareStateDirectory()),
}, resources({ [process.env.APP_REPOSITORY ?? 'graph']: {
  code: process.env.APP_MANIFEST_CODE,
  state: process.env.APP_MANIFEST_STATE,
  adoptSlug: process.env.APP_ADOPT_SLUG,
} }))
