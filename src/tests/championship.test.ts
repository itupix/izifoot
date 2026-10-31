import test from 'node:test'
import assert from 'node:assert/strict'
import { generateSchedule, standings, reorderFixtures } from '../championship-domain'
const teams = (count:number) => Array.from({length:count},(_,i)=>({id:String(i),name:`Team ${i}`,isOwnTeam:i===0}))
for (const count of [2,3,4,5,16,31,32]) {
  for (const double of [false,true]) test(`round robin ${count} teams, return=${double}`,()=>{
    const data = generateSchedule(teams(count),double)
    assert.equal(data.fixtures.length,count*(count-1)/2*(double?2:1))
    const pairs = new Set(data.fixtures.map(f=>double ? `${f.homeTeamId}:${f.awayTeamId}` : [f.homeTeamId,f.awayTeamId].sort().join(':')))
    assert.equal(pairs.size,data.fixtures.length)
    for (const round of new Set(data.fixtures.map(f=>f.round))) {
      const active = data.fixtures.filter(f=>f.round===round).flatMap(f=>[f.homeTeamId,f.awayTeamId])
      assert.equal(new Set(active).size,active.length)
      assert.equal(active.length+(count%2),count)
    }
    assert.equal(data.byeRounds.length,count%2 ? count*(double?2:1) : 0)
    assert.equal(data.fixtures.filter(f=>f.homeTeamId==='0'||f.awayTeamId==='0').length,(count-1)*(double?2:1))
  })
}
test('standings count only scored fixtures and use 3/1/0',()=>{
 const data=generateSchedule(teams(3),false)
 const f=data.fixtures[0];f.homeScore=2;f.awayScore=0
 const rows=standings(data)
 assert.equal(rows[0].teamId,f.homeTeamId);assert.equal(rows[0].points,3);assert.equal(rows[0].goalDifference,2)
 assert.equal(rows.find(r=>r.teamId===f.awayTeamId)?.lost,1)
 f.homeScore=1;f.awayScore=1
 assert.equal(standings(data).filter(r=>r.points===1).length,2)
 f.homeScore=null;f.awayScore=null
 assert.ok(standings(data).every(r=>r.played===0))
})
test('reordering is an exact permutation, dated positions locked, rounds retained',()=>{
 const data=generateSchedule(teams(4),false), ids=data.fixtures.map(f=>f.id)
 data.fixtures[0].kickoffAt='2026-11-01T12:00:00Z'
 assert.throws(()=>reorderFixtures(data,[...ids].reverse()))
 assert.throws(()=>reorderFixtures(data,ids.slice(1)))
 assert.throws(()=>reorderFixtures(data,ids.map(()=>ids[0])))
 const rounds=new Map(data.fixtures.map(f=>[f.id,f.round]))
 const next=[ids[0],...ids.slice(1).reverse()];reorderFixtures(data,next)
 assert.deepEqual(data.fixtures.map(f=>f.id),next)
 assert.ok(data.fixtures.every(f=>f.round===rounds.get(f.id)))
})
