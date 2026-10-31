import { randomUUID } from 'crypto'
export type Participant = { id: string; name: string; isOwnTeam: boolean }
export type Fixture = { id: string; round: number; leg: number; order: number; homeTeamId: string; awayTeamId: string; kickoffAt: string | null; homeScore: number | null; awayScore: number | null; matchId: string | null }
export type ChampionshipData = { teams: Participant[]; fixtures: Fixture[]; byeRounds: {round: number; teamId: string}[] }
export function generateSchedule(teams: Participant[], doubleRoundRobin: boolean): ChampionshipData {
  const rotation: Array<Participant | null> = [...teams]
  if (rotation.length % 2) rotation.push(null)
  const fixtures: Fixture[] = [], byeRounds: ChampionshipData['byeRounds'] = []
  const rounds = rotation.length - 1
  for (let round = 1; round <= rounds; round++) {
    for (let i = 0; i < rotation.length / 2; i++) {
      let home = rotation[i], away = rotation[rotation.length - 1 - i]
      if (!home || !away) { byeRounds.push({ round, teamId: (home || away)!.id }); continue }
      if ((round + i) % 2 === 0) [home, away] = [away, home]
      fixtures.push({ id: randomUUID(), round, leg: 1, order: fixtures.length, homeTeamId: home.id, awayTeamId: away.id, kickoffAt: null, homeScore: null, awayScore: null, matchId: null })
    }
    rotation.splice(1, 0, rotation.pop()!)
  }
  if (doubleRoundRobin) {
    for (const fixture of [...fixtures]) fixtures.push({ ...fixture, id: randomUUID(), round: fixture.round + rounds, leg: 2, order: fixtures.length, homeTeamId: fixture.awayTeamId, awayTeamId: fixture.homeTeamId })
    for (const bye of [...byeRounds]) byeRounds.push({ ...bye, round: bye.round + rounds })
  }
  return { teams, fixtures, byeRounds }
}
export function standings(data: ChampionshipData) {
  const rows = data.teams.map(team => ({teamId: team.id, name: team.name, position: 0, played: 0, won: 0, drawn: 0, lost: 0, goalsFor: 0, goalsAgainst: 0, goalDifference: 0, points: 0}))
  for (const fixture of data.fixtures) {
    if (fixture.homeScore === null || fixture.awayScore === null) continue
    const home = rows.find(r => r.teamId === fixture.homeTeamId)!, away = rows.find(r => r.teamId === fixture.awayTeamId)!
    home.played++; away.played++
    home.goalsFor += fixture.homeScore; home.goalsAgainst += fixture.awayScore
    away.goalsFor += fixture.awayScore; away.goalsAgainst += fixture.homeScore
    if (fixture.homeScore === fixture.awayScore) {home.drawn++; away.drawn++; home.points++; away.points++}
    else { const winner = fixture.homeScore > fixture.awayScore ? home : away, loser = winner === home ? away : home; winner.won++; winner.points += 3; loser.lost++ }
  }
  rows.forEach(row => row.goalDifference = row.goalsFor - row.goalsAgainst)
  rows.sort((a,b) => b.points-a.points || b.goalDifference-a.goalDifference || b.goalsFor-a.goalsFor || a.name.localeCompare(b.name, 'fr') || a.teamId.localeCompare(b.teamId))
  return rows.map(({name, ...row}, index) => ({...row, position:index+1}))
}
export function reorderFixtures(data: ChampionshipData, fixtureIds: string[]) {
  if (fixtureIds.length !== data.fixtures.length || new Set(fixtureIds).size !== fixtureIds.length || fixtureIds.some(id => !data.fixtures.some(f => f.id === id))) throw new Error('Expected a permutation of every fixture')
  const current = [...data.fixtures].sort((a,b) => a.order-b.order)
  if (current.some((fixture,index) => fixture.kickoffAt !== null && fixtureIds[index] !== fixture.id)) throw new Error('Dated fixtures cannot be reordered')
  data.fixtures = fixtureIds.map((id,order) => ({...current.find(f => f.id === id)!,order}))
}
