# Player Roster And Parent Linking

## 1. Summary
- Clear description: CRUD for players, parent contact linking, invitation QR/link generation, and invitation status tracking.
- User problem solved: Lets staff maintain team roster and onboard player/parent accounts.
- Product value: Creates canonical player identity used by attendance, match, and messaging.
- Repository: `izifoot`.
- Status: existing (with legacy compatibility aliases).

## 2. Product Objective
- Why it exists: Team operations require stable player records and contactability.
- Target users: Admin, coach, parent/player (read limited).
- Context of use: Roster setup, player detail management, invite flow.
- Expected outcome: Accurate player records and linked parent/player user identities.

## 3. Scope
Included
- `GET/POST/PUT/DELETE /players` and legacy aliases `/effectif`, `/api/players`, `/api/effectif`.
- `GET /players/:id/invitation-status`.
- `POST /players/:id/invite`, `GET /players/:id/invite/qr`.
- `DELETE /players/:id/parents/:parentId`.

Excluded
- Player portal session endpoints documented in player portal feature.
- Team administration and invite acceptance core.

## 4. Actors
- Admin
Permissions: Full roster management.
Actions: create/update/delete players, send invitations.
Restrictions: club/team scope enforced.
- Coach
Permissions: Full roster management in managed scope.
Actions: same as admin in scope.
Restrictions: no out-of-scope teams.
- Parent
Permissions: read child-related data.
Actions: limited invitation responses via other flows.
Restrictions: no full roster CRUD.
- Player
Permissions: read own context via player endpoints.
Actions: no roster CRUD.
Restrictions: no team-wide mutations.
- Guest
Permissions: none.
Actions: none.
Restrictions: no access.
- Unauthenticated user
Permissions: none.
Actions: none.
Restrictions: no access.
- System
Permissions: validates player payload and parent linkage.
Actions: keeps invite status consistent.
Restrictions: must preserve team relation integrity.

## 5. Entry Points
- UI: web PlayersPage/PlayerDetails, iOS PlayersHome/PlayerDetail.
- Routes: `/players*`, invitation and parent-link subroutes.
- External links: player/parent invite URLs, QR codes.

## 6. User Flows
- Main flow: quick-create player with first name only -> open detail -> complete missing profile data if needed -> send invite -> monitor invitation status.
- Variants: update existing player identity fields.
- Back navigation: return to paginated roster.
- Interruptions: invalid contact info or team mismatch.
- Errors: 403 scope errors, 404 missing player.
- Edge cases: child player without parent contact, stale parent link.

## 7. Functional Behavior
- UI behavior: paginated roster with creation and deletion actions.
- Actions: CRUD player and parent link cleanup.
- States: active player, invited parent pending/accepted.
- Conditions: writable team scope required.
- Validations: player create/update accept minimal payloads and normalize legacy field names; adult account invite requires last name, email, and phone.
- Blocking rules: cannot mutate out-of-scope player.
- Automations: invite token generation for parent/player onboarding.

## 8. Data Model
- `Player.name/first_name/last_name`
Source: roster form.
Purpose: display and identity.
Format: strings.
Constraints: indexed by team and names.
- `Player.teamId`
Source: selected team.
Purpose: scope and grouping.
Format: cuid.
Constraints: required.
- `Player.email/phone` and parent contact fields
Source: roster/invite forms.
Purpose: invitation channel.
Format: nullable strings.
Constraints: normalized in API adapters.

## 9. Business Rules
- Player belongs to one team.
- Player creation requires first name only; last name, phone, email, licence, and position may be completed later.
- Adult player account invitation is blocked until last name, email, and phone are available on the player profile or request overrides.
- Child player account invitation keeps the parent-contact flow: the invite targets a parent account and still requires at least one parent contact channel (`email` or `phone`) in the invite request.
- Invite status endpoint reflects latest account-link state.
- Parent link deletion removes relation but keeps player record.
- Legacy route aliases maintained for backward compatibility.

## 10. State Machine
- Player states: `CREATED`, `UPDATED`, `DELETED`.
- Invite states: `NONE`, `PENDING`, `ACCEPTED`, `EXPIRED/CANCELLED`.
- Triggers: roster mutations and invite operations.
- Invalid transitions: invite on deleted/out-of-scope player.

## 11. UI Components
- Roster list, player detail form, invite modal, QR preview.
- Parent contact cards with unlink action.

## 12. Routes / API / Handlers
- `/players`, `/players/:id` and aliases `/effectif`, `/api/players`, `/api/effectif`.
- `/players/:id/invitation-status`.
- `/players/:id/invite`, `/players/:id/invite/qr`.
- `/players/:id/parents/:parentId`.

## 13. Persistence
- Models: `Player`, `User`, `AccountInvite`, `Attendance`, `DirectMessage`.
- Relations: player-user and player-dependent records.
- Constraints: indexes by `teamId` and identity fields.
- Lifecycle: player deletion cascades/invalidates dependent links by model relation policy.

## 14. Dependencies
- Upstream: club/team setup and authorization scope.
- Downstream: attendance, training roles, match events/scorers, messaging.
- Cross-repo: web+iOS player features depend on these contracts.

## 15. Error Handling
- Validation: missing first name or invalid email format -> 400 on player create/update; missing adult invite prerequisites (`lastName`, `email`, `phone`) -> 400 on account invite.
- Validation: child invite without parent `email` and without parent `phone` -> 400 on account invite.
- Missing data: unknown player -> 404.
- Permissions: scope mismatch -> 403.
- Broken states: orphaned invites/links after manual DB edits.
- Current vs expected: legacy aliases can hide source of truth route usage.

## 16. Security
- Access control: auth + scope enforcement.
- Data exposure: only scoped players are listed/read.
- Guest rules: no access.

## 17. UX Requirements
- Feedback: invite sent status and QR availability.
- Errors: clear differentiation between invalid input and forbidden scope.
- Empty states: no players in team.
- Loading: paginated roster loading with append support.

## 18. Ambiguities & Gaps
- Observed
- Multiple route aliases (`/players`, `/effectif`, `/api/players`, `/api/effectif`) exist.
- Inferred
- Aliases are maintained for legacy clients.
- Missing
- No explicit deprecation timeline for alias routes.
- Tech debt
- Field naming variants increase adapter complexity across repos.

## 19. Recommendations
- Product: define canonical player payload and route set.
- UX: expose invite lifecycle timeline in UI.
- Tech: publish deprecation plan for alias endpoints.
- Security: add anti-spam limits on invite resend.

## 20. Acceptance Criteria
1. Scoped admin/coach can create a player with first name only and update remaining profile fields later.
2. Out-of-scope mutations are denied.
3. Adult player invite endpoint rejects incomplete profiles missing last name, email, or phone and otherwise returns usable invitation metadata.
4. Parent unlink succeeds and updates invitation state views.

## 21. Test Scenarios
- Happy path: quick-create player with first name only, then complete profile and send invite.
- Permissions: coach cannot mutate out-of-scope player.
- Errors: invalid payload or missing adult invite prerequisites rejected.
- Edge cases: invitation status for player with no parent contact.

## 22. Technical References
- `src/server.ts`
- `src/player-payload.ts`
- `src/player-invitation-status.ts`
- `prisma/schema.prisma`
