# Season Management And Scoping

## 1. Summary
- Clear description: Defines club-level season configuration and materialized seasons used to scope trainings, matchdays, matches, and season-based stats.
- User problem solved: Clubs need a reliable way to separate sports activity by season instead of mixing historical and current data.
- Product value: Gives every club a configurable season calendar while keeping a stable backend contract for consumers.
- Repository: `izifoot`.
- Status: existing.

## 2. Product Objective
- Why it exists: Football clubs often run on non-calendar-year seasons and need all sports data attached to the correct season.
- Target users: Admin (configuration), coach (consumption), player/parent (indirect read through scoped views).
- Context of use: Club administration, stats dashboards, training lists, matchday flows, player performance views.
- Expected outcome: A club can configure its season boundaries once and all new sports records resolve to the correct season automatically.

## 3. Scope
Included
- Club season configuration on `GET/PUT /clubs/me`.
- Season catalog on `GET /clubs/me/seasons`.
- Automatic season assignment for trainings, matchdays, and matches.
- Optional season filtering on `/trainings`, `/matchday`, `/matches`, `/attendance`.

Excluded
- Manual reassignment of historical records between seasons.
- Dedicated season archive UI or multi-season comparison endpoints.

## 4. Actors
- Admin
Permissions: configure the club season boundaries and read season metadata.
Actions: update season config, consult current and historical seasons.
Restrictions: retroactive config changes are blocked once materialized seasons contain linked data.
- Coach
Permissions: read season-scoped sports data through existing routes.
Actions: consume training, matchday, match, and attendance lists scoped by `seasonId`.
Restrictions: no direct season configuration write access.
- Player / Parent
Permissions: indirect read through season-scoped endpoints already exposed by product flows.
Actions: view stats or public information already filtered by the consumer app.
Restrictions: no direct season administration routes.
- System
Permissions: materialize seasons and attach records to the correct season.
Actions: resolve season windows, create missing season rows, backfill legacy records.
Restrictions: must preserve historical integrity once seasons already contain data.

## 5. Entry Points
- UI: club administration on web and iOS.
- Routes: `/clubs/me`, `/clubs/me/seasons`, `/trainings`, `/matchday`, `/matches`, `/attendance`.
- API triggers: club settings save, training creation, matchday creation, match creation.

## 6. User Flows
- Main flow: admin opens club settings -> sees current season and configured boundaries -> updates season config before data exists for future seasons.
- Sports flow: coach creates a training, matchday, or standalone match -> backend resolves the season from the club config and event date.
- Stats flow: client loads the current club -> reads `currentSeason` -> uses `seasonId` filters on list endpoints to compute season-only stats.
- Errors: retroactive config change returns conflict once seasons already contain linked data.

## 7. Functional Behavior
- Default club season config is August 1 to July 31 in `Europe/Paris`.
- With default config, on Sunday, July 26, 2026 the active season is `2025-2026`; `2026-2027` starts on Saturday, August 1, 2026.
- `GET /clubs/me` returns `seasonConfig` and `currentSeason`.
- `PUT /clubs/me` accepts partial updates for `name` and `seasonConfig`.
- `GET /clubs/me/seasons` returns materialized seasons sorted by descending `startDate`.
- New trainings and matchdays always derive their `seasonId` from their date and the club config.
- New matches inherit the matchday season when attached to a matchday, otherwise they require a standalone `date` and resolve the season from that date.
- Existing list endpoints accept optional `seasonId` filters so consumers can keep stats season-scoped.

## 8. Data Model
- `Club.seasonStartMonth / seasonStartDay / seasonEndMonth / seasonEndDay / seasonTimezone`
Source: admin configuration.
Purpose: recurring season window definition.
Format: month/day integers plus timezone string.
Constraints: defaults to `08/01 -> 07/31`, timezone defaults to `Europe/Paris`.
- `Season`
Source: materialized by backend.
Purpose: stable historical season record per club.
Format: `id`, `key`, `label`, `startDate`, `endDate`.
Constraints: unique by `(clubId, key)` and `(clubId, startDate, endDate)`.
- `Training.seasonId`, `Plateau.seasonId`, `Match.seasonId`
Source: derived automatically.
Purpose: attach sports records to a materialized season.
Constraints: nullable for legacy rows until backfilled, populated for new writes.
- `Match.date`
Source: standalone match payload or inherited matchday date.
Purpose: resolve standalone matches to a season.
Constraints: required for standalone matches.

## 9. Business Rules
- Backend is the only authority that resolves a date into a season.
- Season windows must cross the year boundary; same-year windows are rejected.
- Consumers must not invent a season label or infer season boundaries client-side.
- Retroactive season config changes are rejected once any materialized season already has linked trainings, matchdays, or matches.
- Historical records are not silently reassigned after season rules change.

## 10. Routes / API / Handlers
- `GET /clubs/me`
Returns club metadata plus `seasonConfig` and `currentSeason`.
- `PUT /clubs/me`
Accepts `{ name?, seasonConfig? }`.
Returns `409` with code `SEASON_CONFIG_RETROACTIVE_CHANGE_NOT_ALLOWED` when a retroactive config change would invalidate historical season data.
- `GET /clubs/me/seasons`
Returns paginated season history for the current club.
- `GET /trainings?seasonId=...`
- `GET /matchday?seasonId=...`
- `GET /matches?seasonId=...`
- `GET /attendance?seasonId=...`

## 11. Persistence
- Models: `Club`, `Season`, `Training`, `Plateau`, `Match`.
- Lifecycle: seasons are created lazily when needed for a club/date pair.
- Legacy handling: startup backfill assigns missing `seasonId` values and standalone match dates when possible.

## 12. Error Handling
- Validation: invalid season config or invalid standalone match date returns `400`.
- Conflict: retroactive config change after season materialization returns `409`.
- Missing data: invalid season filter behaves like existing scoped-resource not found/empty-list patterns.

## 13. Cross-Repo Contract Notes
- Web and iOS should read `currentSeason.id` from `GET /clubs/me` instead of deriving the active season locally.
- Web and iOS should pass `seasonId` to stats-driving list endpoints whenever the UI is intended to be season-specific.
- Consumers must treat `season` as backend-owned metadata and not re-label seasons independently.

## 14. Ambiguities & Gaps
- Observed
- Current clients consume the active season by default; no season switcher is exposed yet.
- Missing
- No dedicated admin workflow exists for browsing or editing past season labels.
- Tech debt
- Season backfill currently runs at application startup from the main server process.

## 15. Recommendations
- Product: add explicit season switching only after current-season flows are stable on all clients.
- Tech: move season materialization and backfill into a dedicated service and background-safe migration flow.
- QA: add route-level coverage for season filters and retroactive config conflicts.

## 16. Acceptance Criteria
1. A club without custom settings uses the default `08/01 -> 07/31` season window.
2. `GET /clubs/me` returns the active materialized season for the current date.
3. Training, matchday, and match writes persist the correct `seasonId`.
4. Standalone matches without `date` are rejected.
5. Stats consumers can fetch season-scoped records using `seasonId`.
6. Retroactive season config changes are rejected once season-linked data exists.

## 17. Test Scenarios
- Happy path: create a training dated July 26, 2026 and verify it resolves to season `2025-2026` with default settings.
- Boundary: create a match dated August 1, 2026 and verify it resolves to `2026-2027`.
- Errors: submit a standalone match without `date` and receive validation failure.
- Conflict: change season boundaries after linked season data exists and receive `409`.

## 18. Technical References
- `src/server.ts`
- `src/season.ts`
- `src/match-payload.ts`
- `prisma/schema.prisma`
