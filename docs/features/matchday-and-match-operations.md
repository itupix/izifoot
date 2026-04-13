# Matchday And Match Operations

## 1. Summary
- Clear description: Manages matchday entities, per-team absences, sharing tokens, matches, events, and schedule generation/commit.
- User problem solved: Coaches need end-to-end orchestration for game day execution.
- Product value: Converts planning into actionable match operations and public communication.
- Repository: `izifoot`.
- Status: existing (some advanced behaviors partial).

## 2. Product Objective
- Why it exists: Matchday is the highest coordination workload in youth football operations.
- Target users: Admin, coach; player/parent read subsets.
- Context of use: Matchday detail and match detail workflows.
- Expected outcome: Consistent matchday summary, playable matches, and accurate events.

## 3. Scope
Included
- `/matchday` CRUD, summary, share/unshare, team absence, repair rotation keys.
- `/matches` CRUD.
- `/matches/:id/events` get/post/delete.
- `/schedule/generate`, `/schedule/commit`.

Excluded
- Public token read endpoint behavior details covered in planning/public feature.
- Direct player portal restrictions covered separately.

## 4. Actors
- Admin
Permissions: full matchday/match management in scope.
Actions: create matchday, adjust metadata, manage matches/events.
Restrictions: scoped to club/team.
- Coach
Permissions: same as admin in managed teams.
Actions: set absences, configure lineups and scores.
Restrictions: out-of-scope forbidden.
- Parent
Permissions: read summaries where authorized/shared.
Actions: consume published info.
Restrictions: no matchday structural writes.
- Player
Permissions: read own convocations via player portal.
Actions: consult summary and status.
Restrictions: no structural writes.
- Guest
Permissions: public token read only.
Actions: view shared matchday.
Restrictions: no private data.
- Unauthenticated user
Permissions: same as guest on public token route.
Actions: open shared URL.
Restrictions: cannot access protected `/matchday`.
- System
Permissions: computes summary mode and match consistency.
Actions: schedule generation and persistence.
Restrictions: must maintain scoped player-team constraints.

## 5. Entry Points
- UI: plateau/matchday pages, match details pages.
- Routes: `/matchday*`, `/matches*`, `/schedule/*`.
- External links: public share URLs.
- API triggers: summary refresh and event logging.

## 6. User Flows
- Main flow: create matchday -> set attendance/absences -> create matches -> update events/scores -> share.
- Variants: generate schedule automatically then commit.
- Back navigation: return from match details to matchday overview.
- Interruptions: stale match references, out-of-scope players.
- Errors: forbidden/validation failures for team or player mismatches.
- Edge cases: deleting matchday with many linked matches/events.

## 7. Functional Behavior
- UI behavior: summary endpoint aggregates convocations and rotation context.
- Actions: mutate matchday metadata, create/update/delete matches, add/remove events.
- States: matchday active/deleted; match `PLANNED/PLAYED/CANCELLED`.
- Conditions: write requires admin/coach scope.
- Validations: match payload + event payload validation helpers.
- Blocking rules: players outside match scope rejected.
- Automations: schedule generation and rotation-key repair endpoints.

## 8. Data Model
- `Plateau` (`matchday`) fields
Source: matchday forms.
Purpose: date/location/competition metadata.
Format: date + strings + flags.
Constraints: indexed by `teamId,date`.
- `Match`
Source: match editor.
Purpose: game units inside matchday.
Format: status, teams, scores, tactic JSON.
Constraints: status enum and relations.
- `MatchEvent`
Source: live events logger.
Purpose: timeline (goals/substitutions).
Format: minute/type/scorer/assist/slot.
Constraints: event type enum.

## 9. Business Rules
- Matchday writes are restricted by team scope.
- Match events must reference scoped players/match teams.
- Summary endpoint supports `includeAllPlayers` variant.
- Share/unshare controls public availability token.

## 10. State Machine
- Matchday states: `DRAFT/ACTIVE` (inferred), `SHARED`, `DELETED`.
- Match states: `PLANNED` -> `PLAYED` or `CANCELLED`.
- Event states: appended and deletable.
- Triggers: API mutations.
- Invalid transitions: event insert on inaccessible match.

## 11. UI Components
- Matchday detail board.
- Match list/editor.
- Event timeline controls.
- Share modal and public link actions.

## 12. Routes / API / Handlers
- `/matchday`, `/matchday/:id`, `/matchday/:id/summary`.
- `/matchday/:id/share`, `/matchday/:id/teams/absence`, `/matchday/:id/repair-rotation-keys`.
- `/matches`, `/matches/:id`, `/matches/:id/events`.
- `/schedule/generate`, `/schedule/commit`.

## 13. Persistence
- Models: `Plateau`, `PlateauShareToken`, `Match`, `MatchTeam`, `MatchTeamPlayer`, `MatchEvent`, `Scorer`.
- Constraints: match-team uniqueness by side; indexed rotation keys.
- Lifecycle: deleting matchday cascades share token and dependent matches/events.

## 14. Dependencies
- Upstream: players, attendance, team setup.
- Downstream: public views, stats, player portal.
- Cross-repo: used by major planning/match screens on web and iOS.

## 15. Error Handling
- Validation: malformed match/event payload rejected.
- Missing data: matchday/match not found.
- Permissions: scope mismatch forbidden.
- Broken states: stale rotation keys or inconsistent lineups.
- Current vs expected: repair endpoint exists, indicating occasional integrity drift.

## 16. Security
- Access control: protected routes except explicit public token route.
- Data exposure: public endpoint should only return share-safe fields.
- Guest rules: guest limited to token-based public read.

## 17. UX Requirements
- Feedback: live save status for event and score updates.
- Errors: differentiate validation vs forbidden.
- Empty states: no matches yet.
- Loading: summary + matches loaded in parallel.

## 18. Ambiguities & Gaps
- Observed
- Duplicate route declarations for some matchday endpoints indicate layered compatibility.
- Inferred
- Product supports multiple competition modes (`PLATEAU`, `MATCH`, `TOURNOI`).
- Missing
- Formal contract for schedule generator input/output schemas.
- Tech debt
- Complex orchestration concentrated in monolithic route handlers.

## 19. Recommendations
- Product: define canonical schedule and summary schema docs.
- UX: expose integrity-repair actions only when needed.
- Tech: isolate matchday domain services and validation modules.
- Security: enforce structured audit logs for score/event changes.

## 20. Acceptance Criteria
1. Scoped admin/coach can create and manage matchday and matches.
2. Event logging persists with proper minute/type validation.
3. Share token grants public read-only access.
4. Out-of-scope player operations are rejected.

## 21. Test Scenarios
- Happy path: create matchday, add match, add events, share.
- Permissions: parent cannot mutate matchday.
- Errors: invalid event payload returns validation error.
- Edge cases: delete shared matchday and verify token invalidation.

## 22. Technical References
- `src/server.ts`
- `src/matchday-contract.ts`
- `src/match-events.ts`
- `src/match-status.ts`
- `src/match-payload.ts`
- `prisma/schema.prisma`
