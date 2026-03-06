import test from 'node:test'
import assert from 'node:assert/strict'
import { buildPlateauMetadataPatch, plateauMetadataSchema, toPublicPlateau } from '../plateau-metadata'

test('plateau metadata validation accepts strict HH:MM and null values', () => {
  const parsed = plateauMetadataSchema.safeParse({
    address: 'Stade Jean Moulin',
    startTime: '09:30',
    meetingTime: null,
  })

  assert.equal(parsed.success, true)
  if (!parsed.success) return
  assert.equal(parsed.data.startTime, '09:30')
  assert.equal(parsed.data.meetingTime, null)
})

test('plateau metadata validation rejects invalid time formats', () => {
  const invalidValues = ['9:30', '24:00', '23:60', '12-30', 'ab:cd']

  for (const value of invalidValues) {
    const parsed = plateauMetadataSchema.safeParse({ startTime: value })
    assert.equal(parsed.success, false)
  }
})

test('partial metadata patch updates only provided fields', () => {
  const patch = buildPlateauMetadataPatch({ startTime: '10:15' })

  assert.deepEqual(patch, { startTime: '10:15' })
  assert.equal('address' in patch, false)
  assert.equal('meetingTime' in patch, false)
})

test('public plateau shape includes new metadata fields', () => {
  const plateau = toPublicPlateau({
    id: 'pl_1',
    date: new Date('2026-03-06T10:00:00.000Z'),
    lieu: 'Terrain central',
    address: '1 rue du Stade',
    startTime: '10:00',
    meetingTime: '09:30',
  })

  assert.equal(plateau.address, '1 rue du Stade')
  assert.equal(plateau.startTime, '10:00')
  assert.equal(plateau.meetingTime, '09:30')
})
