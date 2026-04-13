# Club Team And Account Administration

## 1. Summary
- Clear description: Manages club identity, teams, coach listings, and account invitations.
- User problem solved: Gives direction users tools to structure club organization.
- Product value: Establishes club/team hierarchy used by all sports workflows.
- Repository: `izifoot`.
- Status: existing.

## 2. Product Objective
- Why it exists: Club setup is prerequisite for operational planning and messaging.
- Target users: Admin (primary), coach (read subset).
- Context of use: Initial setup and ongoing team/account maintenance.
- Expected outcome: Consistent club, team, and invited-account records.

## 3. Scope
Included
- `GET/PUT /clubs/me`, `GET /clubs/me/coaches`, `GET /coaches/:id`.
- `GET/POST/PUT/DELETE /teams`.
- `POST /accounts`, `GET /accounts`, `GET /accounts/invitations`.

Excluded
- Authentication token acceptance (auth feature).
- Player roster operations (player feature).

## 4. Actors
- Admin
Permissions: Full CRUD on club/team and account invitations.
Actions: Rename club, manage teams, invite accounts.
Restrictions: Club-bound only.
- Coach
Permissions: Read only limited resources.
Actions: View scoped team/club metadata.
Restrictions: No direction-only write operations.
- Parent
Permissions: No direct administration operations.
Actions: N/A.
Restrictions: blocked.
- Player
Permissions: No direct administration operations.
Actions: N/A.
Restrictions: blocked.
- Guest
Permissions: none.
Actions: N/A.
Restrictions: blocked.
- Unauthenticated user
Permissions: none.
Actions: N/A.
Restrictions: blocked.
- System
Permissions: Enforce club-bound uniqueness and scope.
Actions: Validate team and invitation payloads.
Restrictions: Must preserve referential integrity.

## 5. Entry Points
- UI: Club management page/web, ClubHomeView/iOS.
- Routes: `/clubs/me`, `/teams`, `/accounts*`.
- API triggers: creation and update forms.

## 6. User Flows
- Main flow: direction loads club dashboard -> creates/edits/deletes teams -> invites accounts.
- Variants: list invitations and existing accounts.
- Back navigation: return to team list after modifications.
- Interruptions: duplicate team name in same club.
- Errors: forbidden for non-direction, validation failures.
- Edge cases: deleting team with linked entities.

## 7. Functional Behavior
- UI behavior: fetches club + teams + invitations in one load cycle.
- Actions: rename club, create/update/delete team, create invitation.
- States: loading, ready, mutation pending, mutation error.
- Conditions: direction role required for writes.
- Validations: required `teamId`/role/email for account invite payload.
- Blocking rules: read-only accounts cannot perform writes.
- Automations: invitation status transitions by backend.

## 8. Data Model
- `Club.name`
Source: direction input.
Purpose: club identity.
Format: string.
Constraints: required.
- `Team.name/category/format/clubId`
Source: direction input.
Purpose: operational segmentation.
Format: strings + relation.
Constraints: unique `[clubId,name]`.
- `AccountInvite.*`
Source: invitation form.
Purpose: create pending access for users.
Format: role/email/team mapping.
Constraints: status lifecycle and expiry.

## 9. Business Rules
- Team operations are club-scoped.
- Account invites require valid team in same club.
- Direction-only endpoints reject coach/player/parent writes.
- Coach listing merges existing users and invite metadata.

## 10. State Machine
- Team states: `ACTIVE` or deleted.
- Invite states: `PENDING` -> `ACCEPTED`/`CANCELLED`/`EXPIRED`.
- Transitions: API mutations.
- Invalid transitions: invite acceptance from cancelled/expired.

## 11. UI Components
- Club form, team list/forms, invitation creation modal.
- Coach detail page/view.
- Invitation list table.

## 12. Routes / API / Handlers
- `/clubs/me`, `/clubs/me/coaches`, `/coaches/:id`.
- `/teams` and `/teams/:id`.
- `/accounts`, `/accounts/invitations`.

## 13. Persistence
- Models: `Club`, `Team`, `User`, `AccountInvite`.
- Relations: club-users, club-teams, team-users.
- Constraints: team unique by club; invite indices on club/status.
- Lifecycle: team deletion cascades related scoped entities according to model constraints.

## 14. Dependencies
- Upstream: auth and authorization scope.
- Downstream: players/trainings/matchday/messaging rely on team records.
- Cross-repo: consumed by web club pages and iOS club feature.

## 15. Error Handling
- Validation: malformed payload -> 400.
- Missing data: team or club not found -> 404.
- Permissions: role mismatch -> 403.
- Broken states: delete attempts blocked by dependent data constraints.
- Current vs expected: error payload schema is not formally versioned.

## 16. Security
- Access control: strict direction-only write checks.
- Data exposure: club-scoped selects.
- Guest rules: no access.

## 17. UX Requirements
- Feedback: immediate mutation result feedback.
- Errors: deterministic reason for duplicate/forbidden actions.
- Empty states: no teams/no invites should be explicit.
- Loading: concurrent load of club + teams + invites.

## 18. Ambiguities & Gaps
- Observed
- Team format/category values are string-based and not fully constrained at DB enum level.
- Inferred
- Product expects team templates to drive downstream tactical behavior.
- Missing
- No explicit archival state for teams.
- Tech debt
- Administration logic lives in monolithic route file.

## 19. Recommendations
- Product: define allowed team categories/formats in canonical enum contract.
- UX: add conflict guidance for duplicate team names.
- Tech: extract account-invite service with unit tests.
- Security: add audit trail for admin mutations.

## 20. Acceptance Criteria
1. Direction can create/update/delete team within own club.
2. Non-direction cannot mutate team/club/admin endpoints.
3. Account invite appears in invitation list after creation.
4. Duplicate team name in same club is rejected.

## 21. Test Scenarios
- Happy path: create team then invite coach.
- Permissions: coach write attempt blocked.
- Errors: invalid teamId in invite payload.
- Edge cases: deleting team with linked players.

## 22. Technical References
- `src/server.ts`
- `prisma/schema.prisma`
