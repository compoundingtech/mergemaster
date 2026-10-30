export function plan(nodes) {
  const result = [], active = new Set(), done = new Set()
  function visit(name) {
    if (active.has(name)) throw new Error(`cycle at ${name}`)
    if (done.has(name)) return
    if (!Object.hasOwn(nodes, name)) throw new Error(`missing node ${name}`)
    active.add(name)
    for (const dependency of nodes[name]) visit(dependency)
    active.delete(name)
    done.add(name)
    result.push(name)
  }
  for (const name of Object.keys(nodes)) visit(name)
  return result
}
