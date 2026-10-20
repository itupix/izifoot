import PDFDocument from 'pdfkit'

export function summaryTimeZone(value: unknown): string {
  if (value === undefined) return 'Europe/Paris'
  if (typeof value !== 'string' || !value.trim()) throw new Error('Invalid time zone')
  try { new Intl.DateTimeFormat('fr-FR', { timeZone: value }).format() } catch { throw new Error('Invalid time zone') }
  return value
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
  attendance: Function, drills: Function, catalog: Function,
}) {
  const scope = { ...auth, teamId: training.teamId, clubId: training.clubId ?? auth.clubId }
  const [attendance, rows, catalog] = await Promise.all([
    io.attendance(db, scope, { where: { session_type: 'TRAINING', session_id: training.id, teamId: training.teamId }, include: { player: true } }),
    io.drills(db, scope, training.id),
    io.catalog(db, scope, {}),
  ])
  const players = new Map<string, string>()
  for (const row of attendance) {
    if (row.player?.teamId === training.teamId) players.set(row.playerId, row.player.name)
  }
  const byId = new Map(catalog.map((drill: any) => [drill.id, drill]))
  return {
    ...training,
    players: [...players.values()].sort((a, b) => a.localeCompare(b, 'fr')),
    drills: rows.map((row: any) => {
      const drill = byId.get(row.drillId) as any
      return { title: drill?.title || 'Exercice indisponible', description: descriptionText(drill?.description || '') || 'Descriptif indisponible' }
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
      if (doc.y > doc.page.height - 130) doc.addPage()
      doc.font('Bold').fontSize(12).fillColor('#223047').text(`${index + 1}. ${drill.title}`, { lineGap: 3 })
      doc.moveDown(0.4)
      text(drill.description)
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
