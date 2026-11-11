import test from 'node:test'
import assert from 'node:assert/strict'
import { validAttendanceMonth, attendanceMonthInSeason, renderMonthlyAttendancePdf, monthlyAttendancePlayers } from '../team-attendance-pdf'
import { buildTeamAttendanceReport, loadTeamAttendanceReport } from '../team-attendance-report'
const season = { id:'s',key:'2026-2027',label:'2026-2027',startDate:'2026-07-31T22:00:00Z',endDate:'2027-07-31T21:59:59Z' }
const report = (trainings:any[]=[],players:any[]=[])=>buildTeamAttendanceReport({teamId:'t',season,trainings,players,attendance:[],now:new Date('2026-11-11')})
test('PDF month requires explicit calendar month and checks Paris season boundaries',()=>{
  for(const value of [undefined,'','2026-00','2026-13','2026-1',['2026-10'],'2026-10\n','0000-10'])assert.equal(validAttendanceMonth(value),false)
  assert.equal(validAttendanceMonth('2026-10'),true)
  assert.equal(attendanceMonthInSeason('2026-07',season),false)
  assert.equal(attendanceMonthInSeason('2026-08',season),true)
  assert.equal(attendanceMonthInSeason('2027-07',season),true)
  assert.equal(attendanceMonthInSeason('2027-08',season),false)
})
test('shared loader forbids role and unmanaged team before loading attendance',async()=>{
  assert.equal((await loadTeamAttendanceReport({}, {role:'PLAYER'},'t')).status,403)
  const db={team:{findFirst:async()=>({id:'t',clubId:'c',name:'Test'})}}
  assert.equal((await loadTeamAttendanceReport(db,{role:'COACH',clubId:'c',managedTeamIds:['other']},'t')).status,404)
  assert.equal((await loadTeamAttendanceReport(db,{role:'DIRECTION',clubId:'other'},'t')).status,404)
})
test('shared loader pins exact club team season active roster for both PDF and JSON',async()=>{
  const db={team:{findFirst:async()=>({id:'t',clubId:'c',name:'Équipe'})},club:{findUnique:async()=>({id:'c'})},season:{findUnique:async()=>season},training:{findMany:async(args:any)=>{assert.deepEqual(args.where,{teamId:'t',clubId:'c',seasonId:'s'});return [{id:'a',date:'2026-10-01',status:'PLANNED'}]}},player:{findMany:async(args:any)=>{assert.deepEqual(args.where,{teamId:'t',clubId:'c',is_active:true});return [{id:'p',name:'Zoé',is_active:true}]}},attendance:{findMany:async(args:any)=>{assert.deepEqual(args.where.playerId.in,['p']);assert.deepEqual(args.where.session_id.in,['a']);return [{session_id:'a',playerId:'p',session_type:'TRAINING'}]}}}
  const result=await loadTeamAttendanceReport(db,{role:'COACH',clubId:'c',managedTeamIds:['t']},'t',undefined,new Date('2026-11-11'))
  if(result.status!==undefined)assert.fail(result.error)
  assert.equal(result.report.summary.attendanceRate,100)
  assert.equal(result.team.name,'Équipe')
})
test('PDF renders empty state and multiple pages of players and training groups',async()=>{
  const empty=await renderMonthlyAttendancePdf(report(),'Équipe U13','2026-10')
  assert.equal(empty.subarray(0,5).toString(),'%PDF-')
  const trainings=Array.from({length:8},(_,i)=>({id:`t${i}`,date:`2026-10-${String(i+1).padStart(2,'0')}T15:00:00Z`,status:'PLANNED'}))
  const players=Array.from({length:35},(_,i)=>({id:`p${i}`,name:`Éloïse ${'Nom composé très long '.repeat(4)} ${i}`,is_active:true}))
  const large=await renderMonthlyAttendancePdf(report(trainings,players),'Équipe U13','2026-10')
  assert.ok(large.length>empty.length)
  assert.ok((large.toString('latin1').match(/\/Type \/Page\b/g)||[]).length>=8)
  await assert.rejects(renderMonthlyAttendancePdf(report(),'Équipe','2025-01'),/outside/)
})

test('PDF names and alphabetical order match the UI instead of legacy name fields',()=>{
 const result=monthlyAttendancePlayers(report([], [{id:'z',name:'AAA legacy',first_name:'Zoé',last_name:'Martin',is_active:true},{id:'a',name:'ZZZ legacy',first_name:'André',last_name:'Dupont',is_active:true},{id:'b',name:'Baptiste',is_active:true}]))
 assert.deepEqual(result.map(p=>p.displayName),['André Dupont','Baptiste','Zoé Martin'])
 assert.deepEqual(result.map(p=>p.id),['a','b','z'])
})
