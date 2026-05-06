import test from 'node:test'
import assert from 'node:assert/strict'
import { playerCollectionRouteAliases, playerDetailRouteAliases } from '../player-route-aliases'

test('player collection aliases keep canonical and legacy endpoints aligned', () => {
  assert.deepEqual([...playerCollectionRouteAliases], [
    '/players',
    '/effectif',
    '/api/players',
    '/api/effectif',
  ])
})

test('player detail aliases keep canonical and legacy endpoints aligned', () => {
  assert.deepEqual([...playerDetailRouteAliases], [
    '/players/:id',
    '/effectif/:id',
    '/api/players/:id',
    '/api/effectif/:id',
  ])
})
