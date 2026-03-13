import test from 'node:test'
import assert from 'node:assert/strict'
import {
  canWriteTacticForTeam,
  sortTacticsByUpdatedAtDesc,
  tacticPayloadSchema,
  upsertTacticByTeamAndName,
} from '../tactics'

test('tacticPayloadSchema accepts valid tactic payload', () => {
  const parsed = tacticPayloadSchema.safeParse({
    teamId: 'team-1',
    name: 'Pressing haut',
    formation: '2-1-1',
    points: {
      gk: { x: 50, y: 90 },
      p1: { x: 32, y: 64 },
      p2: { x: 68, y: 64 },
      p3: { x: 50, y: 44 },
      p4: { x: 50, y: 24 },
    },
  })

  assert.equal(parsed.success, true)
})

test('tacticPayloadSchema rejects incomplete points payload', () => {
  const parsed = tacticPayloadSchema.safeParse({
    teamId: 'team-1',
    name: 'Pressing haut',
    formation: '2-1-1',
    points: {
      gk: { x: 50, y: 90 },
      p1: { x: 32, y: 64 },
      p2: { x: 68, y: 64 },
      p3: { x: 50, y: 44 },
    },
  })

  assert.equal(parsed.success, false)
})

test('tacticPayloadSchema rejects out-of-bounds coordinates', () => {
  const parsed = tacticPayloadSchema.safeParse({
    teamId: 'team-1',
    name: 'Pressing haut',
    formation: '2-1-1',
    points: {
      gk: { x: 5, y: 90 },
      p1: { x: 32, y: 64 },
      p2: { x: 68, y: 64 },
      p3: { x: 50, y: 44 },
      p4: { x: 50, y: 24 },
    },
  })

  assert.equal(parsed.success, false)
})

test('canWriteTacticForTeam only allows DIRECTION/COACH on active team', () => {
  assert.equal(canWriteTacticForTeam({ role: 'DIRECTION', teamId: 'team-1' }, 'team-1'), true)
  assert.equal(canWriteTacticForTeam({ role: 'DIRECTION', teamId: 'team-1' }, 'team-2'), false)

  assert.equal(
    canWriteTacticForTeam({ role: 'COACH', teamId: 'team-1', managedTeamIds: ['team-1', 'team-3'] }, 'team-1'),
    true
  )
  assert.equal(
    canWriteTacticForTeam({ role: 'COACH', teamId: 'team-2', managedTeamIds: ['team-1', 'team-3'] }, 'team-1'),
    false
  )
  assert.equal(canWriteTacticForTeam({ role: 'PLAYER', teamId: 'team-1' }, 'team-1'), false)
})

test('upsertTacticByTeamAndName creates then updates existing tactic (case-insensitive name)', async () => {
  const rows: any[] = []

  const delegate = {
    findFirst: async ({ where }: any) => {
      const needle = String(where?.name?.equals || '').toLowerCase()
      return rows.find((row) => row.teamId === where.teamId && row.name.toLowerCase() === needle) || null
    },
    create: async ({ data }: any) => {
      const now = new Date()
      const row = {
        id: `t_${rows.length + 1}`,
        createdAt: now,
        updatedAt: now,
        ...data,
      }
      rows.push(row)
      return row
    },
    update: async ({ where, data }: any) => {
      const idx = rows.findIndex((row) => row.id === where.id)
      if (idx < 0) throw new Error('row not found')
      rows[idx] = { ...rows[idx], ...data, updatedAt: new Date() }
      return rows[idx]
    },
  }

  const created = await upsertTacticByTeamAndName(delegate as any, {
    teamId: 'team-1',
    name: 'Pressing Haut',
    formation: '2-1-1',
    points: {
      gk: { x: 50, y: 90 },
      p1: { x: 32, y: 64 },
      p2: { x: 68, y: 64 },
      p3: { x: 50, y: 44 },
      p4: { x: 50, y: 24 },
    },
  })

  const updated = await upsertTacticByTeamAndName(delegate as any, {
    teamId: 'team-1',
    name: 'pressing haut',
    formation: '1-2-1',
    points: {
      gk: { x: 50, y: 90 },
      p1: { x: 28, y: 64 },
      p2: { x: 72, y: 64 },
      p3: { x: 50, y: 44 },
      p4: { x: 50, y: 24 },
    },
  })

  assert.equal(rows.length, 1)
  assert.equal(updated.id, created.id)
  assert.equal(updated.formation, '1-2-1')
  assert.equal(updated.name, 'pressing haut')
})

test('sortTacticsByUpdatedAtDesc orders most recent first', () => {
  const rows = sortTacticsByUpdatedAtDesc([
    { id: 'a', updatedAt: '2026-03-10T10:00:00.000Z' },
    { id: 'b', updatedAt: '2026-03-12T10:00:00.000Z' },
    { id: 'c', updatedAt: '2026-03-11T10:00:00.000Z' },
  ])

  assert.deepEqual(rows.map((r) => r.id), ['b', 'c', 'a'])
})
