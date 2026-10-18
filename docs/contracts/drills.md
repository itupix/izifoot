# Drill API contract (18 October 2026)

All routes require authentication and retain existing staff/write authorization and team/club scope. Existing error responses remain: 401 authentication, 403 role/scope, 404 missing entity, 503 unavailable drill storage, 502 AI generation failure. Invalid payloads return 400 `{error: Zod.flatten()}`; invalid list category returns 400 `{error:"Invalid drill category"}`.

## Categories and fields

The only category values are `collectif`, `technique`, `jeu`, `autres`, displayed as Collectif, Technique, Jeu, Autres. Forms should default to Autres. Category is required on creation; database default is `autres`.

Drill responses retain `id,userId,clubId,teamId,title,category,description,descriptionHtml,tags,createdAt,updatedAt`. `duration` and `players` are removed. Descriptions authored by users remain untouched.

TrainingDrill responses retain `id,userId,clubId,teamId,trainingId,drillId,order,notes` and, on linkage routes, `meta: Drill|null`. `duration` is removed. Training session scheduling, player attendance and diagram animation timing remain unchanged.

## Catalogue

- GET `/drills`: query `q,category,tag,limit,offset`; response `{items:Drill[],categories:["collectif","technique","jeu","autres"],tags:string[],pagination:{limit,offset,returned}}`. Categories are fixed even for an empty catalogue.
- GET `/drills/:id`: 200 Drill.
- POST `/drills`: `{title:string(1..100),category:enum,description:string(1..2000),tags?:string[]}`; tags max 20 and each 1..32 characters; 201 Drill.
- PUT `/drills/:id`: same supported fields, optional; 200 Drill.
- DELETE `/drills/:id`: unchanged `{ok:true}`.

## Training linkage and AI

- GET `/trainings/:id/drills`: 200 TrainingDrill[] enriched with `meta`.
- POST `/trainings/:id/drills`: `{drillId,notes?:string(<=1000),trainingDrillId?,replaceTrainingDrillId?,id?}`; existing replacement aliases retained; 200 TrainingDrill with meta.
- PUT `/trainings/:id/drills/:trainingDrillId`: `{drillId?,notes?:string(<=1000)|null,order?:integer>=0}`; at least one supported field; 200 TrainingDrill with meta.
- DELETE linkage routes unchanged.
- POST `/trainings/:id/drills/generate-ai`: `{objective:string(10..400),includeDiagrams?:boolean}`; existing response envelope containing generated drill/trainingDrill/diagram items, without retired fields. AI must select a permitted category and no longer generates duration or player-count metadata.

For transition, retired `duration` and `players` sent by older clients are stripped as unknown fields, never stored or returned. A linkage update containing only retired fields returns 400 because it has no supported update. Unsupported categories are rejected, not silently remapped.

## Migration and deployment

Deploy migration `20261018100000_simplify_drill_metadata` with the backend (`npx prisma migrate deploy`). It sets **all existing drills** to `autres`, adds the default and four-value database constraint, and drops Drill.duration, Drill.players and TrainingDrill.duration. It must run only once through migration history; do not rerun the category update as a recurring backfill. Historical metadata is intentionally removed. Deploy updated clients alongside the backend because old clients may require removed response fields. No production database changes are executed by this source change.

A repeatable PostgreSQL migration check is available in `scripts/test-drill-migration.sql`: `psql "$TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f scripts/test-drill-migration.sql`. It uses temporary fixture tables inside a rolled-back transaction and checks historical/valid category reassignment, removed columns, retained descriptions/linkage/notes/order/session duration, category defaults and rejection of invalid values. Run against an isolated test database. The current local PostgreSQL service and Docker daemon were unavailable during implementation, so this integration check has not yet run. `npm start` does not apply migrations automatically; run migration deployment before starting the updated backend.
