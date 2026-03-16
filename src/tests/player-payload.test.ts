import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizePlayerForApi, parsePlayerCreatePayload, parsePlayerUpdatePayload } from '../player-payload'

test('POST payload refuses missing email', () => {
  assert.throws(() => {
    parsePlayerCreatePayload({
      firstName: 'Lina',
      lastName: 'Martin',
      phone: '0611223344',
      primary_position: 'NON DEFINI',
      isChild: false,
    })
  })
})

test('POST payload refuses missing phone', () => {
  assert.throws(() => {
    parsePlayerCreatePayload({
      firstName: 'Lina',
      lastName: 'Martin',
      email: 'lina@example.com',
      primary_position: 'NON DEFINI',
      isChild: false,
    })
  })
})

test('POST payload refuses child without parent names', () => {
  assert.throws(() => {
    parsePlayerCreatePayload({
      firstName: 'Lina',
      lastName: 'Martin',
      email: 'lina@example.com',
      phone: '0611223344',
      primary_position: 'NON DEFINI',
      isChild: true,
      parentFirstName: 'Claire',
    })
  })
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
  assert.equal(parsed.parentFirstName, 'Marie')
  assert.equal(parsed.parentLastName, 'Dupont')
  assert.equal(parsed.licence, 'F12345')
})

test('PUT payload refuses missing email', () => {
  assert.throws(() => {
    parsePlayerUpdatePayload({
      firstName: 'Lina',
      lastName: 'Martin',
      phone: '0611223344',
      primary_position: 'NON DEFINI',
      isChild: false,
    }, {})
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

  assert.equal(parsed.parentFirstName, 'Marie')
  assert.equal(parsed.parentLastName, 'Dupont')
})
