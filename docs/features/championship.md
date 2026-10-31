# Championship API contract v1

Authenticated API, scoped by the existing club and active/managed team rules. Read access follows team access, mutations require DIRECTION or COACH managing the team. All responses use `{ championship: Championship | null, canManage: boolean }`. Error responses use `{ error: string, code: string }` (existing authentication errors retain their established format).

## Resource

A championship is unique per team and season. Omitted season uses the club's current season. Resource fields:

- `id`, `teamId`, `seasonId`, `name`, `doubleRoundRobin`.
- `status`: `DRAFT` or `VALIDATED`; `revision`: integer starting at 1.
- `teams`: `{ id, name, isOwnTeam }[]`; participant IDs are championship-local IDs, not club team IDs.
- `fixtures`: `{ id, round, leg, order, homeTeamId, awayTeamId, kickoffAt, homeScore, awayScore, matchId }[]`.
- `kickoffAt`: ISO timestamp with explicit timezone or null (both date and time are required together); scores and `matchId` are nullable. `round` is 1-based; `order` is 0-based; `leg` is 1 or 2.
- `byeRounds`: `{ round, teamId }[]`, including return-leg rests for odd participant counts.
- `standings`: `{ teamId, position, played, won, drawn, lost, goalsFor, goalsAgainst, goalDifference, points }[]`.

## Endpoints

- `GET /championship?teamId=ID&seasonId=ID`: fetch championship, or null with `canManage` if none exists. `teamId` is required; `seasonId` optional.
- `POST /championship`: `{teamId, seasonId?, name, teams: string[], doubleRoundRobin?: true}`. **teams contains opponent names only**: own team is added automatically from the selected team's persisted name. Total participants 2–32, unique after Unicode normalization, case-folding and trimming, each name 1–120 characters. Generates deterministic round-robin pairings; names and participant list cannot be changed after creation. Returns 201.
- `PATCH /championship/:id/fixtures/:fixtureId`: `{revision, kickoffAt: ISO|null}`. Editable before and after validation. Kickoff must fall inside the championship season. No automatic kickoff is invented.
- `PUT /championship/:id/order`: `{revision, fixtureIds: string[]}`. Exact permutation of all fixture IDs. Dated fixtures must retain their existing positions. Reorders undated fixtures only; sporting rounds and legs never change. Clients can restrict moves to a round. Render calendar using `order`, with round labels retained.
- `POST /championship/:id/validate`: `{revision}`. Dates are optional. Generates exactly one existing Match for each own-team fixture, type `CHAMPIONSHIP`, with its real kickoff or null. Other teams' matches never enter the user's planning. Retrying validation at the current revision is idempotent.
- `PUT /championship/:id/fixtures/:fixtureId/result`: `{revision, homeScore: integer|null, awayScore: integer|null}`. Validated championships only; both scores required or both null to clear, range 0–999. Synchronizes the linked own-team Match's scores and played/status fields. Other fixtures store their scores in the championship.

All mutation responses return the refreshed resource and `canManage`. Every actual mutation increments `revision`. Stale revisions return 409 `REVISION_CONFLICT`; reload before retry. No automatic client retry against a new revision. Mutations are transactional, including linked Match creation/updates.

## Planning and results

Before validation, fixtures stay within the championship editor. After validation, clients render fixtures involving `isOwnTeam` in planning: dated fixtures on their calendar day, undated fixtures in **À programmer**. Use `fixture.matchId` to open the existing match detail. PUT /matches/:id accepts CHAMPIONSHIP for an existing championship match, preserving championship identity; arbitrary standalone matches cannot be converted into championship matches. Planning currently aggregates matchdays and training, so clients must explicitly merge validated own-team championship fixtures from this endpoint. Existing `GET /matches` includes the linked matches and preserves `date: null` for undated CHAMPIONSHIP matches. Its other match fields follow the existing Match contract (`opponentName`, `teams`, `status`, `played`, `teamId`, etc.). Avoid merging both sources into duplicate events.

GET and mutations hydrate linked fixtures from the current Match state: existing Match score editing is reflected in standings, and existing Match date editing is reflected in the calendar. Only PLAYED matches count. Cancelled matches and unplayed fixtures do not count. Championship result entry marks a linked match PLAYED; clearing scores marks it PLANNED. Points: win 3, draw 1, loss 0. Sort points, goal difference, goals scored, then French name order (stable participant ID as final tie-break). This is an indicative table, not federation-specific disciplinary or head-to-head rules.

## Errors and rollout

400 `INVALID_INPUT`; 403 `FORBIDDEN`; 404 `NOT_FOUND`; 409 `CHAMPIONSHIP_EXISTS`, `REVISION_CONFLICT`, `INVALID_STATE`; 500 `INTERNAL_ERROR`. Authentication uses existing middleware (401 where unauthenticated). Teams outside the club return 404. Apply migration `20261031120000_add_championship` and regenerate Prisma before deployment. No data destruction or automatic production migration is performed by this feature.

No participant editing, championship deletion/recreation, official federation synchronization, Android implementation, notifications, or schedule conflict detection is included in v1. Existing user changes to auth/team scoping remain separate; implementation branch was prepared from backend HEAD to avoid committing those changes.

Linked Match deletion through DELETE /matches/:id returns 409 CHAMPIONSHIP_MATCH_PROTECTED; reschedule or cancel instead. Cancelled Match scores are excluded. A Match removed out of band is exposed with matchId null and cleared scores, preserving the fixture without counting stale results. Existing Match updates with the established accepted payload reflect scores/dates on subsequent championship reads; payloads explicitly sending type CHAMPIONSHIP are accepted for existing championship matches only. Changing the match type, opponent, attaching a plateau, or moving outside its championship season is rejected.
