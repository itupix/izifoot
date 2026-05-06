import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizeDrillDescription, toDrillDescriptionHtml, withDrillDescriptionHtml } from '../drill-description'

test('withDrillDescriptionHtml preserves manual drill description without injecting sections', () => {
  const raw = 'Jeu de passes en triangle avec appui-remise et finition rapide.'
  const rendered = withDrillDescriptionHtml({ description: raw })

  assert.equal(rendered.description, raw)
  assert.equal(rendered.descriptionHtml, `<p>${raw}</p>`)
})

test('normalizeDrillDescription keeps paragraph breaks while trimming noisy whitespace', () => {
  const raw = '  Organisation simple  \n\n  Passe et va   '
  const normalized = normalizeDrillDescription(raw)

  assert.equal(normalized, 'Organisation simple\nPasse et va')
})

test('toDrillDescriptionHtml keeps explicit labels when the author wrote them', () => {
  const raw = 'Organisation: carré de 20m\nConsignes: jouer en deux touches'
  const html = toDrillDescriptionHtml(raw)

  assert.equal(
    html,
    '<p><strong>Organisation :</strong> carré de 20m</p><p><strong>Consignes :</strong> jouer en deux touches</p>'
  )
})
