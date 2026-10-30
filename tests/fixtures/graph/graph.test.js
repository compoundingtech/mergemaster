import { plan } from './lib/graph.mjs'

test('dependencies precede dependents', () => {
  expect(plan({ app: ['core'], core: [] })).toEqual(['core', 'app'])
})
test('shared diamond dependencies run once', () => {
  expect(plan({ app: ['left', 'right'], left: ['core'], right: ['core'], core: [] }))
    .toEqual(['core', 'left', 'right', 'app'])
})
test('cycles fail closed', () => {
  expect(() => plan({ left: ['right'], right: ['left'] })).toThrow('cycle')
})
test('missing dependencies fail closed', () => {
  expect(() => plan({ app: ['missing'] })).toThrow('missing node')
})
