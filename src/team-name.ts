function stripDiacritics(value: string) {
  return value.normalize('NFD').replace(/[\u0300-\u036f]/g, '')
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

export function foldTeamNameForCompare(value: string): string {
  return stripDiacritics(String(value || ''))
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim()
}

export function computeAutoTeamName(baseName: string, existingNames: string[]): string {
  const canonicalBase = foldTeamNameForCompare(baseName)
  if (!canonicalBase) return baseName

  const exactBaseRegex = new RegExp(`^${escapeRegExp(canonicalBase)}$`)
  const suffixedRegex = new RegExp(`^${escapeRegExp(canonicalBase)}\\s+(\\d+)$`)
  let hasBaseName = false
  let maxSuffix = 1

  for (const rowName of existingNames) {
    const canonical = foldTeamNameForCompare(rowName)
    if (exactBaseRegex.test(canonical)) {
      hasBaseName = true
      continue
    }
    const m = canonical.match(suffixedRegex)
    if (!m) continue
    const suffix = Number(m[1])
    if (Number.isInteger(suffix) && suffix > maxSuffix) maxSuffix = suffix
  }

  if (!hasBaseName) return baseName
  return `${baseName} ${maxSuffix + 1}`
}
