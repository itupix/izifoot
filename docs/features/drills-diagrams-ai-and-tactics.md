# Drills Diagrams AI And Tactics

## 1. Summary
- Clear description: Provides drill library CRUD, training-drill linkage, diagram CRUD, AI generation endpoints, and tactic entity endpoints.
- User problem solved: Coaches can prepare session content and visual tactical assets.
- Product value: Improves training quality and repeatability.
- Repository: `izifoot`.
- Status: partial (tactics not fully surfaced in all clients).

## 2. Product Objective
- Why it exists: Sports pedagogy requires reusable exercises and visual instructions.
- Target users: Admin, coach.
- Context of use: drills pages, training detail, diagram editor.
- Expected outcome: searchable drill catalog with linked diagrams and optional AI assistance.

## 3. Scope
Included
- `/drills` CRUD.
- `/trainings/:id/drills*` linkage and ordering.
- `/drills/:id/diagrams*`, `/training-drills/:id/diagrams*`, `/diagrams/:id`.
- AI generation endpoints for drills and diagrams.
- `/tactics` CRUD.

Excluded
- Frontend rendering details of diagrams.
- Matchday tactical application rules outside persisted tactic payload.

## 4. Actors
- Admin
Permissions: full drill/diagram/tactic CRUD.
Actions: create catalog and visuals.
Restrictions: scoped by club/team.
- Coach
Permissions: same in managed scope.
Actions: manage drills and diagrams.
Restrictions: no out-of-scope writes.
- Parent
Permissions: no direct writes.
Actions: none.
Restrictions: blocked.
- Player
Permissions: generally read-only via derived contexts.
Actions: consume published training content.
Restrictions: no catalog writes.
- Guest
Permissions: none.
Actions: none.
Restrictions: blocked.
- Unauthenticated user
Permissions: none.
Actions: none.
Restrictions: blocked.
- System
Permissions: can generate AI suggestion payloads.
Actions: stores generated drills/diagrams.
Restrictions: must respect scope and ownership checks.

## 5. Entry Points
- UI: Drills pages and diagram editor in web; Drills views in iOS.
- Routes: drills, training-drills, diagrams, tactics endpoints.
- API triggers: AI generate buttons.

## 6. User Flows
- Main flow: create drill -> attach to training -> create/edit diagram -> reuse.
- Variants: AI-generated drills and AI-generated diagrams.
- Back navigation: return from detail/editor to drill list.
- Interruptions: generation error or insufficient scope.
- Errors: 403 scope, 404 missing drill/diagram.
- Edge cases: training drill linked to removed drill.

## 7. Functional Behavior
- UI behavior: list with pagination and metadata filters.
- Actions: CRUD drill/diagram/tactic and update training-drill order.
- States: draft content, persisted content.
- Conditions: authenticated coach/direction scope.
- Validations: payload shape for drill and diagram data.
- Blocking rules: team scope checks on owned drill/training drill.
- Automations: AI generation endpoints create content artifacts.

## 8. Data Model
- `Drill` fields
Source: drill forms.
Purpose: reusable training unit.
Format: title/category/duration/description/tags.
Constraints: relation to team and author.
- `Diagram` fields
Source: diagram editor payload.
Purpose: tactical visualization data.
Format: JSON data + title + relation ids.
Constraints: linked to drill or trainingDrill.
- `Tactic` fields
Source: tactic API payloads.
Purpose: tactical templates.
Format: JSON/metadata.
Constraints: team scoped.

## 9. Business Rules
- Drill and diagram writes are coach/direction scoped.
- Training drill operations require training scope access.
- AI generation writes artifacts tied to existing drill/training context.
- Tactics endpoint exists as separate resource for advanced usage.

## 10. State Machine
- Drill states: `CREATED` -> `UPDATED` -> `DELETED`.
- Diagram states: same CRUD lifecycle.
- Tactic states: same CRUD lifecycle.
- Triggers: endpoint mutations.
- Invalid transitions: diagram update after deletion.

## 11. UI Components
- Drill list/detail forms.
- Diagram canvas editor and save flow.
- AI generation action buttons.

## 12. Routes / API / Handlers
- `/drills`, `/drills/:id`.
- `/trainings/:id/drills`, `/trainings/:id/drills/:trainingDrillId`.
- `/drills/:id/diagrams*`, `/training-drills/:id/diagrams*`, `/diagrams/:id`.
- `/trainings/:id/drills/generate-ai`.
- `/drills/:id/diagrams/generate-ai`, `/training-drills/:id/diagrams/generate-ai`.
- `/tactics`, `/tactics/:id`.

## 13. Persistence
- Models: `Drill`, `TrainingDrill`, `Diagram`, `Tactic`.
- Relations: drills linked to trainings and diagrams.
- Constraints: scoped ownership and relation consistency.
- Lifecycle: deletion rules should prevent orphan links.

## 14. Dependencies
- Upstream: team scope and training feature.
- Downstream: training execution and possibly match preparation.
- Cross-repo: web/iOS drill modules consume same contracts.

## 15. Error Handling
- Validation: invalid drill/diagram payload rejected.
- Missing data: 404 for unknown resources.
- Permissions: 403 for out-of-scope writes.
- Broken states: orphan trainingDrill/diagram references.
- Current vs expected: tactic coverage appears partial in clients.

## 16. Security
- Access control: auth + scope checks on content resources.
- Data exposure: list endpoints should respect active team scope.
- Guest rules: no access.

## 17. UX Requirements
- Feedback: save success/error for editor operations.
- Errors: generation failures should be explicit.
- Empty states: no drills/diagrams available.
- Loading: paginated loading for large libraries.

## 18. Ambiguities & Gaps
- Observed
- Tactics API exists but is not consistently exposed across clients.
- Inferred
- Tactical module is under active buildout.
- Missing
- Formal schema docs for diagram JSON structure.
- Tech debt
- AI endpoints lack explicit contract documentation for fallback behavior.

## 19. Recommendations
- Product: define MVP boundaries for tactics feature.
- UX: show generation provenance and editability indicators.
- Tech: publish JSON schema for diagram/tactic payloads.
- Security: rate-limit AI generation endpoints.

## 20. Acceptance Criteria
1. Scoped coach/admin can CRUD drills and diagrams.
2. Training drills can be added/reordered/removed.
3. AI generation endpoints return structured, storable outputs.
4. Unauthorized users cannot mutate resources.

## 21. Test Scenarios
- Happy path: create drill, add diagram, attach to training.
- Permissions: parent cannot access write endpoints.
- Errors: invalid diagram payload rejected.
- Edge cases: delete drill with linked training drill.

## 22. Technical References
- `src/server.ts`
- `src/tactics.ts`
- `src/match-tactic.ts`
- `prisma/schema.prisma`
