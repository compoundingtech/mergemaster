import * as Alchemy from 'alchemy'
import { localState } from 'alchemy/State/LocalState'
import * as GitHub from '@overeng/alchemy-github'
import { resources } from './stack.ts'

export default Alchemy.Stack('RepositoryCheckPublishers', {
  providers: GitHub.providers(),
  state: localState(),
}, resources({ [process.env.APP_REPOSITORY ?? 'graph']: {
  code: process.env.APP_MANIFEST_CODE,
  state: process.env.APP_MANIFEST_STATE,
  adoptSlug: process.env.APP_ADOPT_SLUG,
} }))
