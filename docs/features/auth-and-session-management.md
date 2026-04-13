# Auth And Session Management

## 1. Summary
- Clear description: Handles registration, login, logout, invite token lookup, invite acceptance, and authenticated identity retrieval.
- User problem solved: Allows a user to enter the product and bind account access to club/team context.
- Product value: Enables all protected features and role-based navigation.
- Repository: `izifoot`.
- Status: existing.

## 2. Product Objective
- Why it exists: Secure entry point and deterministic role attribution.
- Target users: Admin, coach, parent, player, invited users.
- Context of use: First login, invite onboarding, session restore.
- Expected outcome: Valid token cookie/session, stable `/me` payload.

## 3. Scope
Included
- `POST /auth/register`, `POST /auth/login`, `POST /auth/logout`.
- `GET /auth/invitations/:token`, `POST /auth/invitations/accept`.
- `GET /me`.

Excluded
- Team switching (`/me/team`) handled in authorization/scoping feature.
- Profile editing (`/me/profile`) handled in account/administration features.

## 4. Actors
- Admin
Permissions: Full login/register and invite acceptance.
Actions: Authenticates and enters direction scope.
Restrictions: Cannot bypass invitation status constraints.
- Coach
Permissions: Login/register/invite acceptance.
Actions: Authenticates and receives managed-team scope.
Restrictions: No direction-only operations.
- Parent
Permissions: Login/invite acceptance.
Actions: Authenticates with linked child context.
Restrictions: Write restrictions on coach-direction features.
- Player
Permissions: Login/invite acceptance.
Actions: Authenticates for player-focused features.
Restrictions: No club management permissions.
- Guest
Permissions: Register and invitation token inspection.
Actions: Creates account, checks invite validity.
Restrictions: No protected resources.
- Unauthenticated user
Permissions: Same as guest.
Actions: Token-based onboarding.
Restrictions: No `/me`.
- System
Permissions: Validates credentials, invite expiry/status.
Actions: Issues and clears auth session.
Restrictions: Must enforce role and invite integrity.

## 5. Entry Points
- UI: Home/login/register forms, invite acceptance page.
- Routes: `/auth/*`, `/me`.
- External links: Invite URL with token.
- System triggers: Session restore calling `/me`.
- API triggers: AuthStore/useAuth bootstrap.

## 6. User Flows
- Main flow: Register or login -> session created -> `/me` loaded.
- Variants: Invite token accepted before first login.
- Back navigation: User can logout and return to public home.
- Interruptions: Invalid credentials or expired invite.
- Errors: 400/401 for invalid auth; 404/410 for invalid/expired invite.
- Edge cases: Existing email during registration, invite already consumed.

## 7. Functional Behavior
- UI behavior: Client waits for `/me` to resolve before protected pages.
- Actions: Create account, authenticate, invalidate session.
- States: unauthenticated, authenticating, authenticated, auth-error.
- Conditions: Valid email/password, invite status `PENDING` and not expired.
- Validations: Payload schemas in server handlers.
- Blocking rules: Protected routes require auth middleware.
- Automations: None observed.

## 8. Data Model
- `User.email`
Source: request payload.
Purpose: Unique identity.
Format: string email.
Constraints: unique.
- `User.role`
Source: registration/invitation.
Purpose: authorization baseline.
Format: enum.
Constraints: required.
- `AccountInvite.token/status/expiresAt/userId`
Source: invitation creation and acceptance.
Purpose: controlled onboarding.
Format: string/enum/date/cuid.
Constraints: token unique, status transitions validated.

## 9. Business Rules
- Invite acceptance requires valid token and allowed status.
- Role is assigned from invite when onboarding invited account.
- `/me` returns normalized account payload used by clients.
- Logout invalidates current session token/cookie.

## 10. State Machine
- States: `UNAUTHENTICATED`, `AUTHENTICATED`, `INVITE_PENDING`, `INVITE_ACCEPTED`, `INVITE_EXPIRED`.
- Transitions: login/register -> authenticated; logout -> unauthenticated; accept invite pending -> accepted.
- Triggers: auth endpoints.
- Invalid transitions: accept cancelled/expired invite.

## 11. UI Components
- Pages: home auth forms, invite acceptance page.
- Components: auth form, loading guard.
- Notifications: auth errors shown in client apps.
- Emails: invite delivery handled by invitation feature.
- Links: invite token URL.
- QR codes: not used in core auth.

## 12. Routes / API / Handlers
- `/auth/register`, `/auth/login`, `/auth/logout`.
- `/auth/invitations/:token`, `/auth/invitations/accept`.
- `/me`.
- Handler source: `src/server.ts`.

## 13. Persistence
- Models: `User`, `AccountInvite`.
- Tables: same names via Prisma.
- Relations: `AccountInvite.user`, `AccountInvite.invitedBy`.
- Constraints: unique email, unique invite token.
- Lifecycle: invite created -> pending -> accepted/cancelled/expired.

## 14. Dependencies
- Upstream: session middleware, password hashing/JWT logic.
- Downstream: all protected product features.
- Cross-repo: web/iOS auth stores and route guards.

## 15. Error Handling
- Validation: malformed payload -> 400.
- Network: client fallback to logged-out state.
- Missing data: token not found -> 404.
- Permissions: unauthenticated access -> 401.
- Broken states: invite linked to missing entities.
- Current vs expected: current returns generic errors in some cases; expected should expose stable error codes.

## 16. Security
- Access control: auth middleware for protected routes.
- Data exposure: `/me` only returns current user context.
- Guest rules: guest can only access explicit public auth routes.

## 17. UX Requirements
- Feedback: clear invalid credential and invite status messages.
- Errors: deterministic mapping by status code.
- Empty states: no invite context fallback.
- Loading: blocking loader during session restore.
- Responsive: client responsibility.

## 18. Ambiguities & Gaps
- Observed
- Invite and account field naming includes legacy aliases in clients.
- Inferred
- Token strategy supports both web and mobile session restoration.
- Missing
- No explicit machine-readable error catalog.
- Tech debt
- Mixed naming conventions (`firstName` vs `first_name`) increase parser complexity.

## 19. Recommendations
- Product: publish canonical auth error code list.
- UX: standardize invite failure messages across clients.
- Tech: enforce one response naming convention.
- Security: add explicit rate-limit docs for auth endpoints.

## 20. Acceptance Criteria
1. Valid credentials authenticate and return `/me` with role.
2. Invalid credentials return deterministic 401 error payload.
3. Expired invite cannot be accepted.
4. Logout invalidates next protected request.

## 21. Test Scenarios
- Happy path: register -> login -> `/me`.
- Permissions: unauthenticated `/me` denied.
- Errors: bad token invite returns expected status.
- Edge cases: accepting already accepted invite.

## 22. Technical References
- `src/server.ts`
- `prisma/schema.prisma`
