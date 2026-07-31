import test from 'node:test'
import assert from 'node:assert/strict'
import { buildMatchdayMetadataPatch, matchdayCreateSchema, matchdayMetadataSchema, toPublicMatchday } from '../matchday-metadata'

test('matchday metadata validation accepts strict HH:MM and null values', () => {
  const parsed = matchdayMetadataSchema.safeParse({
    address: 'Stade Jean Moulin',
    startTime: '09:30',
    meetingTime: null,
  })

  assert.equal(parsed.success, true)
  if (!parsed.success) return
  assert.equal(parsed.data.startTime, '09:30')
  assert.equal(parsed.data.meetingTime, null)
})

test('matchday metadata validation rejects invalid time formats', () => {
  const invalidValues = ['9:30', '24:00', '23:60', '12-30', 'ab:cd']

  for (const value of invalidValues) {
    const parsed = matchdayMetadataSchema.safeParse({ startTime: value })
    assert.equal(parsed.success, false)
  }
})

test('partial metadata patch updates only provided fields', () => {
  const patch = buildMatchdayMetadataPatch({ startTime: '10:15' })

  assert.deepEqual(patch, { startTime: '10:15' })
  assert.equal('address' in patch, false)
  assert.equal('meetingTime' in patch, false)
})

test('matchday create validation requires opponent for MATCH competitions', () => {
  const parsed = matchdayCreateSchema.safeParse({
    date: '2026-08-02T08:00:00.000Z',
    competitionType: 'MATCH',
    matchVenue: 'HOME',
  })

  assert.equal(parsed.success, false)
})

test('matchday create validation requires matchVenue for MATCH competitions', () => {
  const parsed = matchdayCreateSchema.safeParse({
    date: '2026-08-02T08:00:00.000Z',
    competitionType: 'MATCH',
    opponentName: 'FC Montfermeil',
  })

  assert.equal(parsed.success, false)
})

test('matchday create validation requires lieu for away MATCH competitions', () => {
  const parsed = matchdayCreateSchema.safeParse({
    date: '2026-08-02T08:00:00.000Z',
    competitionType: 'MATCH',
    opponentName: 'FC Montfermeil',
    matchVenue: 'AWAY',
  })

  assert.equal(parsed.success, false)
})

test('matchday create validation accepts home MATCH competitions without lieu', () => {
  const parsed = matchdayCreateSchema.safeParse({
    date: '2026-08-02T08:00:00.000Z',
    competitionType: 'MATCH',
    opponentName: 'FC Montfermeil',
    matchVenue: 'HOME',
  })

  assert.equal(parsed.success, true)
  if (!parsed.success) return
  assert.equal(parsed.data.matchVenue, 'HOME')
})

test('matchday create validation accepts away MATCH competitions with lieu', () => {
  const parsed = matchdayCreateSchema.safeParse({
    date: '2026-08-02T08:00:00.000Z',
    lieu: 'Stade municipal',
    competitionType: 'MATCH',
    opponentName: 'FC Montfermeil',
    matchVenue: 'AWAY',
  })

  assert.equal(parsed.success, true)
  if (!parsed.success) return
  assert.equal(parsed.data.opponentName, 'FC Montfermeil')
})

test('public matchday shape includes new metadata fields', () => {
  const matchday = toPublicMatchday({
    id: 'pl_1',
    date: new Date('2026-03-06T10:00:00.000Z'),
    lieu: 'Terrain central',
    address: '1 rue du Stade',
    startTime: '10:00',
    meetingTime: '09:30',
  })

  assert.equal(matchday.address, '1 rue du Stade')
  assert.equal(matchday.startTime, '10:00')
  assert.equal(matchday.meetingTime, '09:30')
  assert.equal('matchVenue' in matchday, false)
})
