import test from 'node:test'
import assert from 'node:assert/strict'
import { registerChampionshipRoutes } from '../championship'
function harness() {
 const handlers = new Map<string,any>(), rows:any[] = [], matches:any[] = []
 const db:any = {
  team:{findFirst:async({where}:any)=>where.id==='team'&&where.clubId==='club'?{id:'team',clubId:'club',name:'Izifoot'}:null},
  season:{findFirst:async()=>({id:'season'}),findUnique:async()=>({id:'season',startDate:new Date('2026-08-01'),endDate:new Date('2027-08-01')})},
  championship:{findUnique:async({where}:any)=>rows.find(r=>where.id?r.id===where.id:r.teamId===where.teamId_seasonId.teamId&&r.seasonId===where.teamId_seasonId.seasonId)||null,
   create:async({data}:any)=>{if(rows.length)throw {code:'P2002'};const r={id:'championship',revision:1,status:'DRAFT',...data};rows.push(r);return r},
   updateMany:async({where}:any)=>{const row=rows.find(r=>r.id===where.id&&r.revision===where.revision);if(row)row.revision++;return {count:row?1:0}},
   update:async({where,data}:any)=>{const row=rows.find(r=>r.id===where.id);Object.assign(row,data);return row}},
  match:{findMany:async()=>matches,create:async({data}:any)=>{const row={id:`match${matches.length}`,status:'PLANNED',...data,teams:data.teams.create};matches.push(row);return row},update:async({where,data}:any)=>Object.assign(matches.find(m=>m.id===where.id),data)},
  matchTeam:{updateMany:async({where,data}:any)=>{Object.assign(matches.find(m=>m.id===where.matchId).teams.find((t:any)=>t.side===where.side),data)}},
 }
 db.$transaction=async(fn:any)=>{const snapshot=structuredClone({rows,matches});try{return await fn(db)}catch(error){rows.splice(0,rows.length,...snapshot.rows);matches.splice(0,matches.length,...snapshot.matches);throw error}}
 const app:any={};for(const method of ['get','post','patch','put'])app[method]=(path:string,...args:any[])=>handlers.set(`${method} ${path}`,args.at(-1))
 registerChampionshipRoutes(app,{db,auth:()=>{},scope:()=>({teamId:'team',clubId:'club'}),writeTeam:async()=>({id:'team'}),season:async()=>({id:'season'})})
 const coach={id:'user',clubId:'club',role:'COACH',managedTeamIds:['team']}
 async function call(method:string,path:string,body:any={},params:any={},user:any=coach){let status=200,payload:any;const res:any={status:(value:number)=>{status=value;return res},json:(value:any)=>{payload=value;return res}};await handlers.get(`${method} ${path}`)({auth:user,body,params,query:{teamId:'team'}},res);return {status,payload}}
 return {call,rows,matches,coach}
}
test('API draft, validation, scheduling, results and revision guard',async()=>{
 const h=harness()
 assert.deepEqual((await h.call('get','/championship')).payload,{championship:null,canManage:true})
 const created=await h.call('post','/championship',{teamId:'team',name:'Ligue',teams:['A','B']})
 assert.equal(created.status,201);assert.equal(created.payload.championship.fixtures.length,6);assert.equal(h.matches.length,0)
 const validated=await h.call('post','/championship/:id/validate',{revision:1},{id:'championship'})
 assert.equal(validated.status,200);assert.equal(h.matches.length,4);assert.ok(h.matches.every(m=>m.date===null));assert.equal(validated.payload.championship.revision,2)
 await h.call('post','/championship/:id/validate',{revision:2},{id:'championship'});assert.equal(h.matches.length,4)
 assert.equal((await h.call('post','/championship/:id/validate',{revision:1},{id:'championship'})).status,409)
 const fixture=validated.payload.championship.fixtures.find((f:any)=>f.matchId)
 const params={id:'championship',fixtureId:fixture.id}
 assert.equal((await h.call('patch','/championship/:id/fixtures/:fixtureId',{revision:2,kickoffAt:'2026-11-05T18:30:00+01:00'},params)).status,200)
 assert.equal(new Date(h.matches.find(m=>m.id===fixture.matchId).date).toISOString(),'2026-11-05T17:30:00.000Z')
 const scored=await h.call('put','/championship/:id/fixtures/:fixtureId/result',{revision:3,homeScore:3,awayScore:1},params)
 assert.equal(scored.payload.championship.standings[0].points,3)
 assert.equal(h.matches.find(m=>m.id===fixture.matchId).status,'PLAYED')
 const match=h.matches.find(m=>m.id===fixture.matchId);match.teams.find((t:any)=>t.side==='away').score=4
 const read=await h.call('get','/championship')
 assert.equal(read.payload.championship.fixtures.find((f:any)=>f.id===fixture.id).awayScore,4)
})
test('API forbids readers writes and rejects invalid or duplicate inputs without changes',async()=>{
 const h=harness(),reader={...h.coach,role:'PLAYER'}
 assert.equal((await h.call('post','/championship',{teamId:'team',name:'Ligue',teams:['A']},{},reader)).status,403)
 assert.equal((await h.call('post','/championship',{teamId:'team',name:'Ligue',teams:[' izifoot ']})).status,400)
 await h.call('post','/championship',{teamId:'team',name:'Ligue',teams:['A']})
 assert.equal((await h.call('post','/championship',{teamId:'team',name:'Ligue',teams:['A']})).status,409)
 const id=h.rows[0].data.fixtures[0].id
 assert.equal((await h.call('put','/championship/:id/fixtures/:fixtureId/result',{revision:1,homeScore:0,awayScore:0},{id:'championship',fixtureId:id})).status,409)
 assert.equal(h.rows[0].revision,1)
 assert.equal((await h.call('patch','/championship/:id/fixtures/:fixtureId',{revision:1,kickoffAt:'2025-11-05T18:30:00Z'},{id:'championship',fixtureId:id})).status,400)
 assert.equal(h.rows[0].revision,1)
 assert.equal((await h.call('patch','/championship/:id/fixtures/:fixtureId',{revision:1,kickoffAt:'2026-11-05'},{id:'championship',fixtureId:id})).status,400)
})
