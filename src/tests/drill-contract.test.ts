import test from 'node:test'
import assert from 'node:assert/strict'
import { DRILL_CATEGORIES, drillCreateSchema, drillUpdateSchema, trainingDrillCreateSchema, trainingDrillUpdateSchema } from '../drill-contract'

test('catalogue accepts only the four categories and requires no duration or player count', () => {
  for (const category of DRILL_CATEGORIES) {
    assert.equal(drillCreateSchema.parse({ title: 'Passes', category, description: 'Circulation du ballon' }).category, category)
  }
  for (const category of ['autre', 'echauffement', 'Technique', '', null]) {
    assert.equal(drillCreateSchema.safeParse({ title: 'Passes', category, description: 'Circulation' }).success, false)
    assert.equal(drillUpdateSchema.safeParse({ category }).success, false)
  }
})

test('legacy clients cannot persist retired drill metadata', () => {
  const result = drillCreateSchema.parse({ title: 'Passes', category: 'autres', description: 'Circulation', duration: 20, players: 'Tous' })
  assert.equal('duration' in result, false)
  assert.equal('players' in result, false)
  assert.deepEqual(drillUpdateSchema.parse({ title: 'Nouveau titre', duration: 1, players: 'Variable' }), { title: 'Nouveau titre' })
})

test('training linkage drops legacy duration and retains replacement identifiers', () => {
  assert.deepEqual(trainingDrillCreateSchema.parse({ drillId: 'passes', duration: 20, trainingDrillId: 'existing', notes: 'Consigne' }), { drillId: 'passes', trainingDrillId: 'existing', notes: 'Consigne' })
  assert.equal(trainingDrillUpdateSchema.safeParse({ duration: 20 }).success, false)
  assert.equal(trainingDrillUpdateSchema.safeParse({}).success, false)
  assert.deepEqual(trainingDrillUpdateSchema.parse({ notes: null, order: 0, duration: 20 }), { notes: null, order: 0 })
})
