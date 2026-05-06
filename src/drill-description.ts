function escapeHtml(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

export function normalizeDrillDescription(value: string | null | undefined) {
  return String(value || '')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .split('\n')
    .map((line) => line.replace(/\s+/g, ' ').trim())
    .filter(Boolean)
    .join('\n')
}

export function toDrillDescriptionHtml(value: string | null | undefined) {
  const lines = normalizeDrillDescription(value)
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)

  if (!lines.length) return ''

  return lines.map((line) => {
    const md = line.match(/^\*\*(.+?)\*\*\s*(.*)$/)
    if (md) {
      return `<p><strong>${escapeHtml(md[1].trim())}</strong> ${escapeHtml(md[2])}</p>`
    }
    const plain = line.match(/^([^:]+)\s*:\s*(.*)$/)
    if (plain) {
      return `<p><strong>${escapeHtml(plain[1].trim())} :</strong> ${escapeHtml(plain[2])}</p>`
    }
    return `<p>${escapeHtml(line)}</p>`
  }).join('')
}

export function withDrillDescriptionHtml<T extends { description?: string | null, descriptionHtml?: string | null }>(
  drill: T
): Omit<T, 'description' | 'descriptionHtml'> & { description: string, descriptionHtml: string } {
  const description = normalizeDrillDescription(drill?.description)
  const existingHtml = typeof drill?.descriptionHtml === 'string' ? drill.descriptionHtml.trim() : ''

  return {
    ...drill,
    description,
    descriptionHtml: existingHtml || toDrillDescriptionHtml(description),
  }
}
