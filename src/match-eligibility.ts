type PlateauAttendanceRow = {
  playerId: string
  session_type: string
  present?: boolean | null
}

// Eligibility for match composition:
// - present players are eligible
// - explicitly convoked players are also eligible
// - if no attendance rows exist yet, return null (no filtering)
export function buildEligiblePlayerIdsFromPlateauAttendance(rows: PlateauAttendanceRow[]): Set<string> | null {
  if (!rows.length) return null

  const attendanceMap = new Map<string, boolean | null>()
  const convokeSet = new Set<string>()

  for (const row of rows) {
    if (row.session_type === 'PLATEAU_CONVOKE') {
      convokeSet.add(row.playerId)
      continue
    }
    if (row.present === true) {
      attendanceMap.set(row.playerId, true)
      continue
    }
    if (row.present === false || row.session_type === 'PLATEAU_ABSENT') {
      attendanceMap.set(row.playerId, false)
      continue
    }
    if (row.session_type === 'PLATEAU') {
      attendanceMap.set(row.playerId, true)
      continue
    }
  }

  const eligible = new Set<string>()
  for (const [playerId, present] of attendanceMap.entries()) {
    if (present === true) eligible.add(playerId)
  }
  for (const playerId of convokeSet) eligible.add(playerId)
  return eligible
}
