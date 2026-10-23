import test from 'node:test'
import assert from 'node:assert/strict'
import { trainingMaterials } from '../training-materials'
const drill = (id: string) => ({ id, drillId: `catalog-${id}` })
const diagram = (id: string, frames: any[]) => ({ trainingDrillId: id, data: JSON.stringify({ frames }) })
const cones = (n: number) => Array.from({ length: n }, () => ({ type: 'cone' }))
test('equipment uses maxima across steps and successive exercises, with stable order', () => {
  const result = trainingMaterials([drill('a'), drill('b')], [
    diagram('a', [{ items: cones(3) }, { items: [...cones(5), { type: 'ball' }] }]),
    diagram('b', [{ items: [...cones(2), { type: 'cup' }, { type: 'post' }, { type: 'player', color: 'red' }, { type: 'player', color: 'blue' }] }]),
  ])
  assert.deepEqual(result, { items: [
    { type: 'cup', label: 'Coupelle', quantity: 1 }, { type: 'cone', label: 'Cônes', quantity: 5 },
    { type: 'ball', label: 'Ballon', quantity: 1 }, { type: 'post', label: 'Poteau', quantity: 1 },
    { type: 'bib', label: 'Chasubles', quantity: null },
  ], drillCount: 2, missingDiagramCount: 0 })
})
test('session override takes precedence over catalog and latest diagram wins', () => {
  assert.equal(trainingMaterials([drill('a')], [
    { drillId: 'catalog-a', data: { items: cones(9) } },
    diagram('a', [{ items: cones(2) }]), diagram('a', [{ items: cones(4) }]),
  ]).items[0].quantity, 2)
})
test('catalog fallback accepts legacy items, without counting players as equipment', () => {
  assert.deepEqual(trainingMaterials([drill('a')], [{ drillId: 'catalog-a', data: { items: [{ type: 'player' }, { type: 'arrow' }] } }]),
    { items: [], drillCount: 1, missingDiagramCount: 0 })
})
test('missing and malformed diagrams expose partial completeness; empty diagrams are valid', () => {
  const result = trainingMaterials([drill('a'), drill('b'), drill('c'), drill('d')], [
    { trainingDrillId: 'a', data: '{bad json' }, { trainingDrillId: 'b', data: { frames: [{ items: null }] } },
    diagram('c', [{ items: [] }]),
  ])
  assert.deepEqual(result, { items: [], drillCount: 4, missingDiagramCount: 3 })
  assert.deepEqual(trainingMaterials([], []), { items: [], drillCount: 0, missingDiagramCount: 0 })
})
