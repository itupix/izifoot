import test from 'node:test'
import assert from 'node:assert/strict'
import {
  assertPlayerAccountInvitePrerequisites,
  DEFAULT_PLAYER_PRIMARY_POSITION,
  normalizePlayerForApi,
  parsePlayerCreatePayload,
  parsePlayerUpdatePayload,
} from '../player-payload'

test('POST payload only requires firstName', () => {
  const parsed = parsePlayerCreatePayload({
    firstName: 'Lina',
  })

  assert.equal(parsed.firstName, 'Lina')
  assert.equal(parsed.lastName, '')
  assert.equal(parsed.email, '')
  assert.equal(parsed.phone, '')
  assert.equal(parsed.primary_position, DEFAULT_PLAYER_PRIMARY_POSITION)
})

test('POST payload refuses child without parent names', () => {
  const parsed = parsePlayerCreatePayload({
    firstName: 'Lina',
    lastName: 'Martin',
    email: 'lina@example.com',
    phone: '0611223344',
    primary_position: 'NON DEFINI',
    isChild: true,
  })
  assert.equal(parsed.parentFirstName, null)
  assert.equal(parsed.parentLastName, null)
  assert.equal(parsed.email, '')
  assert.equal(parsed.phone, '')
})

test('POST payload defaults missing primary_position to NON DEFINI', () => {
  const parsed = parsePlayerCreatePayload({
    firstName: 'Lina',
    lastName: 'Martin',
  })

  assert.equal(parsed.primary_position, DEFAULT_PLAYER_PRIMARY_POSITION)
})

test('POST payload accepts primary_position = NON DEFINI', () => {
  const parsed = parsePlayerCreatePayload({
    firstName: 'Lina',
    lastName: 'Martin',
    email: 'lina@example.com',
    phone: '0611223344',
    primary_position: 'NON DEFINI',
    isChild: false,
  })

  assert.equal(parsed.primary_position, 'NON DEFINI')
})

test('normalizePlayerForApi returns coherent firstName + lastName + name', () => {
  const normalized = normalizePlayerForApi({
    id: 'p1',
    first_name: 'Lina',
    last_name: 'Martin',
    name: 'Legacy Name',
    is_child: false,
  })

  assert.equal(normalized.firstName, 'Lina')
  assert.equal(normalized.lastName, 'Martin')
  assert.equal(normalized.name, 'Lina Martin')
})

test('normalizePlayerForApi exposes team and club context when available', () => {
  const normalized = normalizePlayerForApi({
    id: 'p1',
    first_name: 'Lina',
    last_name: 'Martin',
    teamId: 'team-1',
    teamName: 'U11 A',
    clubId: 'club-1',
    clubName: 'FC Test',
  })

  assert.equal(normalized.teamId, 'team-1')
  assert.equal(normalized.teamName, 'U11 A')
  assert.equal(normalized.clubId, 'club-1')
  assert.equal(normalized.clubName, 'FC Test')
})

test('normalizePlayerForApi exposes roster activity fields', () => {
  const normalized = normalizePlayerForApi({
    id: 'p1',
    first_name: 'Lina',
    last_name: 'Martin',
    is_active: false,
    deactivated_at: '2026-07-26T12:00:00.000Z',
  })

  assert.equal(normalized.isActive, false)
  assert.equal(normalized.is_active, false)
  assert.equal(normalized.deactivatedAt, '2026-07-26T12:00:00.000Z')
  assert.equal(normalized.deactivated_at, '2026-07-26T12:00:00.000Z')
})

test('compatibility aliases are accepted', () => {
  const parsed = parsePlayerCreatePayload({
    prenom: 'Noah',
    nom: 'Dupont',
    email: 'noah@example.com',
    phone: '0600000000',
    primary_position: 'NON DEFINI',
    enfant: true,
    parent_first_name: 'Marie',
    parent_last_name: 'Dupont',
    license: 'F12345',
  })

  assert.equal(parsed.firstName, 'Noah')
  assert.equal(parsed.lastName, 'Dupont')
  assert.equal(parsed.isChild, true)
  assert.equal(parsed.parentFirstName, null)
  assert.equal(parsed.parentLastName, null)
  assert.equal(parsed.licence, 'F12345')
})

test('POST payload refuses invalid email when provided', () => {
  assert.throws(() => {
    parsePlayerCreatePayload({
      firstName: 'Lina',
      email: 'invalid-email',
    })
  })
})

test('PUT payload updates concatenated name fields from aliases', () => {
  const parsed = parsePlayerUpdatePayload({
    first_name: 'Lina',
    last_name: 'Martin',
    email: 'lina@example.com',
    phone: '0611223344',
    primary_position: 'NON DEFINI',
    enfant: false,
  }, {})

  const normalized = normalizePlayerForApi({
    ...parsed,
    first_name: parsed.firstName,
    last_name: parsed.lastName,
    name: `${parsed.firstName} ${parsed.lastName}`.trim(),
    is_child: parsed.isChild,
  })

  assert.equal(normalized.name, 'Lina Martin')
})

test('PUT payload preserves existing optional fields when omitted', () => {
  const parsed = parsePlayerUpdatePayload({
    firstName: 'Lina',
    email: 'lina.new@example.com',
  }, {
    first_name: 'Lina',
    last_name: 'Martin',
    email: 'lina.old@example.com',
    phone: '0611223344',
    primary_position: 'ATTAQUANT',
    is_child: false,
  })

  assert.equal(parsed.lastName, 'Martin')
  assert.equal(parsed.email, 'lina.new@example.com')
  assert.equal(parsed.phone, '0611223344')
  assert.equal(parsed.primary_position, 'ATTAQUANT')
})

test('PUT payload keeps requested teamId when provided', () => {
  const parsed = parsePlayerUpdatePayload({
    firstName: 'Lina',
    teamId: 'team-2',
  }, {
    first_name: 'Lina',
    last_name: 'Martin',
    primary_position: 'ATTAQUANT',
    teamId: 'team-1',
    is_child: false,
  })

  assert.equal(parsed.teamId, 'team-2')
})

test('PUT payload accepts parentPrenom/parentNom aliases when child', () => {
  const parsed = parsePlayerUpdatePayload({
    firstName: 'Noah',
    lastName: 'Dupont',
    email: 'noah@example.com',
    phone: '0600000000',
    primary_position: 'NON DEFINI',
    isChild: true,
    parentPrenom: 'Marie',
    parentNom: 'Dupont',
  }, {})

  assert.equal(parsed.parentFirstName, null)
  assert.equal(parsed.parentLastName, null)
})

test('player account invite requires lastName, email and phone for non-child players', () => {
  assert.throws(() => {
    assertPlayerAccountInvitePrerequisites({
      first_name: 'Lina',
      last_name: '',
      email: null,
      phone: null,
      is_child: false,
    })
  })
})

test('player account invite accepts request email and phone overrides for non-child players', () => {
  assert.doesNotThrow(() => {
    assertPlayerAccountInvitePrerequisites({
      first_name: 'Lina',
      last_name: 'Martin',
      email: null,
      phone: null,
      is_child: false,
    }, {
      email: 'lina@example.com',
      phone: '0611223344',
    })
  })
})

test('player account invite keeps child flow unchanged', () => {
  assert.doesNotThrow(() => {
    assertPlayerAccountInvitePrerequisites({
      first_name: 'Noah',
      is_child: true,
    })
  })
})
