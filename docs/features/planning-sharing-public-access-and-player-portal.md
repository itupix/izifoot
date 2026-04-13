# Planning Sharing Public Access And Player Portal

## 1. Summary
- Clear description: Handles generic planning documents, planning share links/QR, public read routes, and player JWT portal endpoints for matchday summaries.
- User problem solved: Supports tactical board sharing and lightweight player-facing access without full app auth.
- Product value: Extends operational data to external/public or role-constrained consumption.
- Repository: `izifoot`.
- Status: partial (legacy routes and mixed contracts).

## 2. Product Objective
- Why it exists: Coaches need to share planning/matchday information externally and to invited players.
- Target users: Admin/coach for creation; players/parents/guests for consumption.
- Context of use: QR links, public pages, player quick-access links.
- Expected outcome: controlled read-only sharing with token-based security.

## 3. Scope
Included
- `/plannings` CRUD + share + QR (`/plannings/:id/share`, `/plannings/:id/qr`, `/s/:token`).
- `/public/matchday/:token`.
- Player portal endpoints: `/player/accept`, `/player/login`, `/player/me`, `/player/matchday`, `/player/matchday/:id/summary`, RSVP routes.

Excluded
- Full authenticated app behavior.
- Matchday structural writes.

## 4. Actors
- Admin
Permissions: create/update/delete/share planning and matchday share token.
Actions: publish links and QR assets.
Restrictions: scope checks still apply.
- Coach
Permissions: same in managed scope.
Actions: create shares and distribute.
Restrictions: no unmanaged team sharing.
- Parent
Permissions: consume shared/public/player portal views.
Actions: read shared data and RSVP via dedicated links.
Restrictions: no write operations.
- Player
Permissions: token-authenticated portal read and RSVP.
Actions: view own convocations and summaries.
Restrictions: tied to token scope and convocated context.
- Guest
Permissions: public token routes only.
Actions: read shared matchday/planning.
Restrictions: cannot access protected resources.
- Unauthenticated user
Permissions: same as guest for token routes.
Actions: consume shared links.
Restrictions: no private endpoints.
- System
Permissions: generates and validates share/player tokens.
Actions: returns sanitized public payloads.
Restrictions: must deny invalid or expired tokens.

## 5. Entry Points
- UI: public matchday page, invite/accept/player links.
- Routes: `/plannings*`, `/s/:token`, `/public/matchday/:token`, `/player/*`.
- External links: QR codes and direct URLs.

## 6. User Flows
- Main flow: coach creates planning -> shares token -> recipient opens public link.
- Variants: player receives invite/login token and opens personal portal.
- Back navigation: public pages are standalone.
- Interruptions: invalid/expired token.
- Errors: 401/403/404 depending on token validity and scope.
- Edge cases: player token limited to one matchday scope.

## 7. Functional Behavior
- UI behavior: public pages read-only, no protected write controls.
- Actions: create share tokens, retrieve by token, generate QR.
- States: token active, expired, revoked/deleted.
- Conditions: only authorized users can create shares.
- Validations: token parsing and scope checks.
- Blocking rules: player portal denies non-convocated access.
- Automations: token generation and optional expiry handling.

## 8. Data Model
- `Planning` and `ShareToken`
Source: planning editor and share actions.
Purpose: store board data and sharable access token.
Format: JSON/string data + token.
Constraints: unique `[userId,date]` planning and unique token.
- `PlateauShareToken`
Source: matchday share action.
Purpose: public matchday access.
Format: unique token + expiry.
Constraints: relation with `Plateau`.
- Player token claims (JWT, inferred)
Source: invite/login endpoints.
Purpose: scoped player portal access.
Format: signed token payload.
Constraints: scope validation.

## 9. Business Rules
- Shared links are read-only.
- Token endpoints must not reveal unauthorized internal data.
- Player summary route checks convocated participation.
- RSVP endpoints rely on player token context.

## 10. State Machine
- Share states: `NOT_SHARED` -> `SHARED` -> `UNSHARED/EXPIRED`.
- Player portal auth states: `NO_TOKEN` -> `TOKEN_VALID` -> `TOKEN_INVALID/EXPIRED`.
- Triggers: share creation/deletion and token-based access requests.
- Invalid transitions: portal access outside scoped matchday.

## 11. UI Components
- QR code displays.
- Public matchday pages.
- Player portal summary views.

## 12. Routes / API / Handlers
- `/plannings`, `/plannings/:id`, `/plannings/:id/share`, `/plannings/:id/qr`, `/s/:token`.
- `/public/matchday/:token`.
- `/player/accept`, `/player/login`, `/player/me`, `/player/matchday`, `/player/matchday/:id/summary`, `/rsvp/p`, `/rsvp/a`.

## 13. Persistence
- Models: `Planning`, `ShareToken`, `PlateauShareToken`, `AccountInvite` (for some flows).
- Relations: planning-share and matchday-share relations.
- Constraints: unique tokens and reference integrity.
- Lifecycle: share token created/revoked/expired.

## 14. Dependencies
- Upstream: auth/authorization, matchday and planning data.
- Downstream: web and iOS public/player consumption.
- Cross-repo: public pages and invite flows rely directly on these contracts.

## 15. Error Handling
- Validation: malformed token rejected.
- Missing data: token not found -> not found response.
- Permissions: unauthorized token scope denied.
- Broken states: tokens pointing to deleted resources.
- Current vs expected: response contracts vary between public and player routes.

## 16. Security
- Access control: token-based access for public/player routes.
- Data exposure: should return minimum safe payload for unauthenticated users.
- Guest rules: only tokenized endpoints allowed.

## 17. UX Requirements
- Feedback: explicit expired/invalid link states.
- Errors: user-facing text should not leak internals.
- Empty states: shared resource exists but contains no items.
- Loading: fast token validation before rendering.

## 18. Ambiguities & Gaps
- Observed
- Multiple public/player link routes coexist (legacy and current).
- Inferred
- Migration from older invitation/player-link flows is ongoing.
- Missing
- Unified token policy documentation (TTL, revocation semantics).
- Tech debt
- Share and player-portal logic spread across large server module.

## 19. Recommendations
- Product: define one canonical public-sharing model per resource type.
- UX: harmonize expired-link messaging across clients.
- Tech: centralize token issuance/validation library.
- Security: formalize token TTL defaults and revocation paths.

## 20. Acceptance Criteria
1. Authorized user can create and revoke planning or matchday share links.
2. Public token endpoints return read-only scoped payloads.
3. Invalid/expired tokens are rejected deterministically.
4. Player portal blocks access to non-convocated matchday summary.

## 21. Test Scenarios
- Happy path: create share token and open public page.
- Permissions: unauthorized user cannot create share.
- Errors: expired token returns expected error state.
- Edge cases: resource deleted after token creation.

## 22. Technical References
- `src/server.ts`
- `src/matchday-contract.ts`
- `prisma/schema.prisma`
