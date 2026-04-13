# Authorization And Team Scoping

## 1. Summary
- Clear description: Enforces role permissions and active team scope for read/write operations.
- User problem solved: Prevents cross-team data leakage and unauthorized writes.
- Product value: Multi-team clubs stay secure and predictable.
- Repository: `izifoot`.
- Status: existing.

## 2. Product Objective
- Why it exists: Role alone is insufficient; team boundary must be enforced.
- Target users: Admin, coach, parent, player, system.
- Context of use: Every protected endpoint and message flow.
- Expected outcome: Same actor receives only authorized team data.

## 3. Scope
Included
- Auth middleware and team scope helpers in `src/server.ts`.
- `PUT /me/team` active team switch.
- Read/write scope checks across endpoints.

Excluded
- Invite creation policy details handled in account administration feature.
- Client navigation decisions handled in web/iOS repos.

## 4. Actors
- Admin
Permissions: Full club scope, optional team locking.
Actions: Select active team, manage all team data when unscoped.
Restrictions: Must still belong to same club.
- Coach
Permissions: Managed-team scope only.
Actions: Read/write within managed teams.
Restrictions: Cannot select unmanaged team.
- Parent
Permissions: Linked child team read and limited intent actions.
Actions: Read child-related schedules/messages.
Restrictions: No direction/coach writes.
- Player
Permissions: Own linked team read and player-portal actions.
Actions: Access player endpoints.
Restrictions: Restricted to convocated contexts.
- Guest
Permissions: None on protected scope.
Actions: N/A.
Restrictions: blocked by middleware.
- Unauthenticated user
Permissions: None.
Actions: N/A.
Restrictions: blocked by middleware.
- System
Permissions: Calculates readable team ids and write scope.
Actions: Resolves team, club, and role constraints.
Restrictions: Must fail closed when scope unknown.

## 5. Entry Points
- UI: Team scope picker in web and iOS.
- Routes: `PUT /me/team`, protected routes with middleware.
- System triggers: Middleware per request.
- API triggers: All authenticated clients.

## 6. User Flows
- Main flow: user logs in -> team scope resolved -> protected request authorized.
- Variants: direction user with no active team can read all club teams.
- Back navigation: change team scope then revisit pages.
- Interruptions: invalid team selection denied.
- Errors: 403 forbidden, 401 unauthenticated.
- Edge cases: parent without valid linked child team.

## 7. Functional Behavior
- UI behavior: clients send `X-Team-Id`/`X-Active-Team-Id` equivalent headers.
- Actions: set active team, resolve readable team list, block writes.
- States: global club scope, single team scope, no-access scope.
- Conditions: role, managedTeamIds, linked player, explicit team selection.
- Validations: team existence in user club.
- Blocking rules: write operations require valid writable scope.
- Automations: none.

## 8. Data Model
- `User.teamId`
Source: selected active team.
Purpose: default scope.
Format: cuid or null.
Constraints: must reference team in same club.
- `User.managedTeamIds`
Source: coach role assignment.
Purpose: allowed team set.
Format: string array.
Constraints: used for authorization checks.
- Linked player relations
Source: `User.linkedPlayerUserId` + `Player.teamId`.
Purpose: parent/player scoping.
Format: relation lookup.
Constraints: team consistency checks.

## 9. Business Rules
- Direction can operate globally when no active team.
- Coach can only access managed teams.
- Parent/player read scope derives from linked child/player context.
- Unauthorized team id always returns forbidden.

## 10. State Machine
- States: `NO_SCOPE`, `CLUB_SCOPE`, `TEAM_SCOPE`, `FORBIDDEN`.
- Transitions: login -> resolved scope; `PUT /me/team` updates scope.
- Triggers: request middleware + explicit team switch.
- Invalid transitions: team switch to non-managed team.

## 11. UI Components
- Team selector controls in web/iOS.
- Route guards and role guards in clients.
- Error banners for forbidden responses.

## 12. Routes / API / Handlers
- `PUT /me/team`.
- Middleware/helpers in `src/server.ts` (read/write scope resolution).

## 13. Persistence
- Models: `User`, `Team`, `Player`.
- Relations: user-team, user-club, parent-player link.
- Constraints: scope checks enforce relation integrity at runtime.

## 14. Dependencies
- Upstream: authenticated identity.
- Downstream: every business endpoint.
- Cross-repo: team scope stores in web (`useTeamScope`) and iOS (`TeamScopeStore`).

## 15. Error Handling
- Validation: invalid team id -> 400/404.
- Network: client retries with same scope.
- Permissions: forbidden responses for out-of-scope operations.
- Broken states: user linked to deleted team.
- Current vs expected: current often returns message strings; expected should include stable machine code.

## 16. Security
- Access control: centralized middleware and helper guards.
- Data exposure: scoped queries with `teamId` filters.
- Guest rules: denied on protected routes.

## 17. UX Requirements
- Feedback: explicit forbidden reason when team is invalid.
- Empty states: no team available for coach must be surfaced.
- Loading: scope initialization before data requests.

## 18. Ambiguities & Gaps
- Observed
- Scope logic is implemented inline in large server file.
- Inferred
- Team scope is the canonical isolation boundary in product design.
- Missing
- Dedicated endpoint to preview effective permissions.
- Tech debt
- Scope logic duplication across handlers increases regression risk.

## 19. Recommendations
- Product: define role/scope matrix in a shared contract file.
- UX: show why user is blocked (role vs team mismatch).
- Tech: extract authorization module with unit tests.
- Security: add audit logs for denied write attempts.

## 20. Acceptance Criteria
1. Coach cannot read/write unmanaged team data.
2. Direction can switch team and observe scoped data changes.
3. Parent/player only see linked-team content.
4. Unauthorized writes return 403.

## 21. Test Scenarios
- Happy path: direction global scope reads all teams.
- Permissions: coach switch to unmanaged team denied.
- Errors: deleted team selection fails safely.
- Edge cases: linked child moved to another team.

## 22. Technical References
- `src/server.ts`
- `prisma/schema.prisma`
