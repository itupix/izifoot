import PDFDocument from 'pdfkit'
import { createHash } from 'node:crypto'
import { parseSummaryDiagram, drawSummaryDiagram } from './training-summary-diagram'

export function summaryTimeZone(value: unknown): string {
  if (value === undefined) return 'Europe/Paris'
  if (typeof value !== 'string' || !value.trim()) throw new Error('Invalid time zone')
  try { new Intl.DateTimeFormat('fr-FR', { timeZone: value }).format() } catch { throw new Error('Invalid time zone') }
  return new Intl.DateTimeFormat('fr-FR', { timeZone: value }).resolvedOptions().timeZone
}

// Bump when rendering, fonts, or content semantics change to invalidate saved PDFs.
export const TRAINING_SUMMARY_RENDERER_VERSION = '2-columns-first-frame-v1'

function canonicalJSON(value: any): string {
  if (value === undefined) return 'null'
  if (value instanceof Date) return JSON.stringify(value.toISOString())
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(',')}}`
  return JSON.stringify(value)
}

export function trainingSummaryVersion(summary: any, timeZone: string): string {
  const content = {
    renderer: TRAINING_SUMMARY_RENDERER_VERSION,
    timeZone: summaryTimeZone(timeZone),
    training: { id: summary.id, teamId: summary.teamId, clubId: summary.clubId, date: new Date(summary.date).toISOString(), endTime: summary.endTime ?? null, status: summary.status, observations: summary.observations ?? null, updatedAt: summary.updatedAt ?? null },
    players: summary.players,
    drills: summary.drills,
    dependencies: summary.versionDependencies ?? [],
  }
  return createHash('sha256').update(canonicalJSON(content)).digest('hex')
}

export function descriptionText(value: string): string {
  return value.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<li\b[^>]*>/gi, '\n- ').replace(/<br\s*\/?\s*>/gi, '\n')
    .replace(/<\/(p|div|h[1-6]|ul|ol)>/gi, '\n').replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'")
    .replace(/&#(x[0-9a-f]+|[0-9]+);/gi, (_, code) => {
      const number = code[0].toLowerCase() === 'x' ? parseInt(code.slice(1), 16) : Number(code)
      return number > 0 && number <= 0x10ffff ? String.fromCodePoint(number) : ''
    }).replace(/\n[ \t]+/g, '\n').replace(/\n{3,}/g, '\n\n').trim()
}

export async function loadTrainingSummary(db: any, auth: any, training: any, io: {
  attendance: Function, drills: Function, catalog: Function, diagrams?: Function,
}) {
  const scope = { ...auth, teamId: training.teamId, clubId: training.clubId ?? auth.clubId }
  const [attendance, rows, catalog] = await Promise.all([
    io.attendance(db, scope, { where: { session_type: 'TRAINING', session_id: training.id, teamId: training.teamId }, include: { player: true } }),
    io.drills(db, scope, training.id),
    io.catalog(db, scope, {}),
  ])
  const diagrams = io.diagrams && rows.length ? await io.diagrams(db, scope, {
    where: { OR: [{ trainingDrillId: { in: rows.map((row: any) => row.id) } }, { drillId: { in: rows.map((row: any) => row.drillId) }, trainingDrillId: null }] },
    orderBy: [{ updatedAt: 'desc' }, { id: 'asc' }],
  }) : []
  const players = new Map<string, string>()
  for (const row of attendance) {
    if (row.player?.teamId === training.teamId) players.set(row.playerId, row.player.name)
  }
  const byId = new Map(catalog.map((drill: any) => [drill.id, drill]))
  return {
    ...training,
    versionDependencies: rows.map((row: any) => {
      const selected = diagrams.find((diagram: any) => diagram.trainingDrillId === row.id)
        ?? diagrams.find((diagram: any) => !diagram.trainingDrillId && diagram.drillId === row.drillId)
      return { id: row.id, drillId: row.drillId, order: row.order, notes: row.notes ?? null, diagram: selected ? { id: selected.id, data: selected.data, updatedAt: selected.updatedAt } : null }
    }),
    players: [...players.values()].sort((a, b) => a.localeCompare(b, 'fr')),
    drills: rows.map((row: any) => {
      const drill = byId.get(row.drillId) as any
      const sessionDiagram = diagrams.find((diagram: any) => diagram.trainingDrillId === row.id)
      const diagram = sessionDiagram ?? diagrams.find((diagram: any) => !diagram.trainingDrillId && diagram.drillId === row.drillId)
      return { diagram: diagram ? parseSummaryDiagram(diagram.data) : null, diagramSource: diagram && !sessionDiagram ? 'catalog' : 'session', title: drill?.title || 'Exercice indisponible', description: descriptionText(drill?.description || '') || 'Descriptif indisponible' }
    }),
  }
}

export function renderTrainingSummary(summary: any, timeZone: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: 48, bufferPages: true, info: { Title: 'Résumé de la séance' } })
    doc.registerFont('Body', require.resolve('dejavu-fonts-ttf/ttf/DejaVuSans.ttf'))
    doc.registerFont('Bold', require.resolve('dejavu-fonts-ttf/ttf/DejaVuSans-Bold.ttf'))
    const chunks: Buffer[] = []
    doc.on('data', (chunk: Buffer) => chunks.push(chunk))
    doc.on('end', () => resolve(Buffer.concat(chunks)))
    doc.on('error', reject)
    const date = new Date(summary.date)
    const text = (value: string, size = 11) => { doc.font('Body').fontSize(size).fillColor('#223047').text(value.trim(), { lineGap: 4 }); doc.moveDown(0.5) }
    const heading = (value: string) => {
      if (doc.y > doc.page.height - 125) doc.addPage()
      doc.font('Bold').fontSize(15).fillColor('#14664d').text(value); doc.moveDown(0.6)
    }
    doc.font('Bold').fontSize(24).fillColor('#14664d').text('Résumé de la séance')
    doc.moveDown()
    text(`Date : ${new Intl.DateTimeFormat('fr-FR', { timeZone, day: '2-digit', month: '2-digit', year: 'numeric' }).format(date)}`)
    text(`Horaires : ${new Intl.DateTimeFormat('fr-FR', { timeZone, hour: '2-digit', minute: '2-digit' }).format(date)} - ${summary.endTime || 'Heure de fin non renseignée'}`)
    if (summary.status === 'CANCELLED') text('Statut : Annulée')
    heading('Observations')
    text(summary.observations?.trim() ? summary.observations : 'Aucune observation.')
    heading(`Joueurs présents (${summary.players.length})`)
    text(summary.players.length ? summary.players.join('\n') : 'Aucun joueur présent enregistré.')
    heading('Exercices de la séance')
    if (!summary.drills.length) text('Aucun exercice enregistré.')
    summary.drills.forEach((drill: any, index: number) => {
      const frame = drill.diagram?.frames[0]
      const width = doc.page.width - 96
      const columnWidth = (width - 18) / 2
      const diagramHeight = frame ? columnWidth * drill.diagram.height / drill.diagram.width : 0
      const title = `${index + 1}. ${drill.title}`
      doc.font('Bold').fontSize(12)
      const titleHeight = doc.heightOfString(title, { width, lineGap: 3 }) + 10
      if (doc.y + titleHeight + Math.max(45, diagramHeight) > doc.page.height - 48) doc.addPage()
      const exerciseTitle = (continued = false) => {
        doc.font('Bold').fontSize(12).fillColor('#223047').text(`${title}${continued ? ' (suite)' : ''}`, 48, doc.y, { width, lineGap: 3 })
        doc.moveDown(0.4)
      }
      exerciseTitle()
      if (!frame) {
        text(drill.description)
        if (drill.diagram?.invalid) text('Diagramme indisponible.', 10)
        return
      }
      const top = doc.y
      drawSummaryDiagram(doc, drill.diagram, frame, 48 + columnWidth + 18, top, columnWidth, diagramHeight)
      doc.x = 48
      doc.y = top
      let remaining = drill.description.trim()
      let firstPage = true
      while (remaining) {
        const startY = doc.y
        const availableHeight = doc.page.height - 48 - startY
        doc.font('Body').fontSize(11)
        const options = { width: columnWidth, lineGap: 4 }
        let end = remaining.length
        if (doc.heightOfString(remaining, options) > availableHeight) {
          let low = 0, high = remaining.length
          while (low < high) {
            const middle = Math.ceil((low + high) / 2)
            if (doc.heightOfString(remaining.slice(0, middle), options) <= availableHeight) low = middle
            else high = middle - 1
          }
          end = low
          const breakAt = Math.max(remaining.lastIndexOf(' ', end), remaining.lastIndexOf('\n', end))
          if (breakAt > end / 2) end = breakAt + 1
          if (end > 0 && /[\uD800-\uDBFF]/.test(remaining[end - 1])) end--
        }
        if (!end) { doc.addPage(); exerciseTitle(true); firstPage = false; continue }
        doc.fillColor('#223047').text(remaining.slice(0, end).trimEnd(), 48, startY, options)
        remaining = remaining.slice(end).trimStart()
        if (remaining) {
          doc.addPage()
          exerciseTitle(true)
          firstPage = false
        }
      }
      doc.y = Math.max(doc.y, firstPage ? top + diagramHeight : doc.y) + 12
      doc.x = 48
      if (drill.diagram.invalid) text('Diagramme indisponible.', 10)
    })
    const pages = doc.bufferedPageRange()
    for (let index = pages.start; index < pages.start + pages.count; index++) {
      doc.switchToPage(index)
      const bottom = doc.page.margins.bottom
      doc.page.margins.bottom = 0
      doc.font('Body').fontSize(9).fillColor('#667085').text(`${index + 1} / ${pages.count}`, 48, doc.page.height - 34, { lineBreak: false, align: 'right', width: doc.page.width - 96 })
      doc.page.margins.bottom = bottom
    }
    doc.end()
  })
}
