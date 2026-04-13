# Training Lifecycle Attendance And Roles

## 1. Summary
- Clear description: Creates, updates, deletes trainings; tracks attendance, player intent, role assignments, and training drills.
- User problem solved: Coaches need operational control of sessions and participant status.
- Product value: Central workflow for weekly team operations.
- Repository: `izifoot`.
- Status: existing.

## 2. Product Objective
- Why it exists: Deliver actionable training planning with roster-level assignment data.
- Target users: Admin, coach (full), parent/player (intent subset).
- Context of use: Planning timeline and training detail views.
- Expected outcome: Reliable training schedule with synchronized attendance and roles.

## 3. Scope
Included
- `/trainings` CRUD.
- `/trainings/:id/intent` get/post.
- `/trainings/:trainingId/attendance` put and `/attendance` list/post.
- `/trainings/:id/roles` get/put.
- `/trainings/:id/drills` get/post/put/delete and AI generation endpoint.

Excluded
- Matchday-specific attendance and matches.
- Drill library master CRUD (documented in drills feature).

## 4. Actors
- Admin
Permissions: full training CRUD within scope.
Actions: create sessions, adjust status, manage attendance and roles.
Restrictions: scope limited by club/team rules.
- Coach
Permissions: same as admin in managed scope.
Actions: same operations.
Restrictions: cannot write unmanaged team data.
- Parent
Permissions: training intent only for linked child.
Actions: set present/absent intent.
Restrictions: no session structural edits.
- Player
Permissions: training intent only for self context.
Actions: set intent.
Restrictions: no session structural edits.
- Guest
Permissions: none.
Actions: none.
Restrictions: no access.
- Unauthenticated user
Permissions: none.
Actions: none.
Restrictions: no access.
- System
Permissions: computes intent summary and role consistency.
Actions: sync attendance and role assignment records.
Restrictions: must enforce player-team coherence.

## 5. Entry Points
- UI: planning page, training detail page (web/iOS).
- Routes: `/trainings*`, `/attendance`, `/trainings/:id/roles`, `/trainings/:id/drills*`.
- System triggers: summary recomputation after writes.

## 6. User Flows
- Main flow: create training -> manage attendance -> assign roles -> attach drills.
- Variants: parent/player submit intent before coach attendance review.
- Back navigation: return to planning list.
- Interruptions: forbidden write due to scope.
- Errors: invalid date/status, unknown player assignment.
- Edge cases: training with zero players, cancelled training state.

## 7. Functional Behavior
- UI behavior: detail view aggregates training, players, attendance, roles, drills.
- Actions: mutate schedule metadata, attendance booleans, role map, drill order.
- States: `PLANNED`, `CANCELLED` observed; intent states `PRESENT/ABSENT/UNKNOWN`.
- Conditions: intent endpoint restricted to parent/player roles.
- Validations: payload schema checks and scoped player filtering.
- Blocking rules: linked child must belong to training team.
- Automations: AI drill generation endpoint seeds training drills.

## 8. Data Model
- `Training.date/status/endTime/teamId`
Source: training forms.
Purpose: schedule definition.
Format: ISO date, status string, HH:MM.
Constraints: indexed by `teamId,date`.
- `Attendance.session_type/session_id/playerId/present`
Source: attendance toggles.
Purpose: participation tracking.
Format: enum-like string + ids + bool.
Constraints: unique per user/session/player.
- `TrainingRoleAssignment.trainingId/role/playerId`
Source: role editor.
Purpose: tactical responsibilities.
Format: strings + relation ids.
Constraints: scoped player consistency.

## 9. Business Rules
- Only parent/player can set training intent endpoint.
- Coach/direction manage structural training data.
- Attendance upsert is scoped to training session and player.
- Role assignments must reference players in same team scope.

## 10. State Machine
- Training states: `PLANNED` <-> `CANCELLED`.
- Intent states: `UNKNOWN` -> `PRESENT`/`ABSENT`.
- Attendance states: `UNSET` -> `PRESENT`/`ABSENT`.
- Triggers: detail mutations and intent posts.
- Invalid transitions: intent update by unauthorized roles.

## 11. UI Components
- Training list cards.
- Training detail forms.
- Attendance sheet/table.
- Role assignment editor.
- Drill selection and ordering widgets.

## 12. Routes / API / Handlers
- `/trainings`, `/trainings/:id`.
- `/trainings/:id/intent`.
- `/trainings/:trainingId/attendance`.
- `/attendance`.
- `/trainings/:id/roles`.
- `/trainings/:id/drills` and `/trainings/:id/drills/generate-ai`.

## 13. Persistence
- Models: `Training`, `Attendance`, `TrainingRoleAssignment`, `TrainingDrill`.
- Relations: training-attendance, training-roles, training-drills.
- Constraints: unique attendance composite key; ordered training drills.
- Lifecycle: deleting training removes dependent records by relations.

## 14. Dependencies
- Upstream: team setup and roster availability.
- Downstream: stats, player dashboards, matchday preparation.
- Cross-repo: heavy use in web/iOS planning detail flows.

## 15. Error Handling
- Validation: malformed date/time/status rejected.
- Network: clients refresh on mutation failures.
- Missing data: training/player not found.
- Permissions: intent and write restrictions enforced.
- Broken states: stale role assignments after player deletion.
- Current vs expected: expected explicit role-assignment error codes not always present.

## 16. Security
- Access control: auth + role checks + team scope.
- Data exposure: attendance and roles scoped by team.
- Guest rules: no access.

## 17. UX Requirements
- Feedback: immediate attendance/role save feedback.
- Errors: clear forbidden vs validation errors.
- Empty states: no drills or no players available.
- Loading: parallel data load for training detail.

## 18. Ambiguities & Gaps
- Observed
- Training status uses string values instead of strict enum in model.
- Inferred
- Additional statuses may be planned but not documented.
- Missing
- Formal contract for role names list.
- Tech debt
- Training domain logic concentrated in one large server file.

## 19. Recommendations
- Product: publish allowed training statuses and role vocab.
- UX: show stale-data conflict handling when concurrent edits occur.
- Tech: extract training service with typed contracts.
- Security: add mutation audit trails for attendance/roles.

## 20. Acceptance Criteria
1. Admin/coach can CRUD training in scope.
2. Parent/player can set intent only for linked context.
3. Attendance and roles persist and reload consistently.
4. Unauthorized structural edits are denied.

## 21. Test Scenarios
- Happy path: create training and assign attendance/roles/drills.
- Permissions: parent cannot edit training metadata.
- Errors: invalid player in role assignment rejected.
- Edge cases: training cancellation with existing attendance rows.

## 22. Technical References
- `src/server.ts`
- `src/attendance.ts`
- `src/training-role-assignments.ts`
- `prisma/schema.prisma`
