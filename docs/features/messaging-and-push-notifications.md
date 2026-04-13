# Messaging And Push Notifications

## 1. Summary
- Clear description: Supports team announcement feed, direct coach-player conversations, reactions/read tracking, unread counts, and push token/badge operations.
- User problem solved: Enables asynchronous communication inside team scope.
- Product value: Keeps staff, players, and parents synchronized.
- Repository: `izifoot`.
- Status: existing.

## 2. Product Objective
- Why it exists: Operational communication is critical between trainings and matchdays.
- Target users: Admin, coach, parent, player.
- Context of use: messages tabs, notification refresh loops.
- Expected outcome: scoped conversation access and reliable unread indicators.

## 3. Scope
Included
- `/messages/conversations`, `/messages/conversations/:id/messages` read/write.
- `/team-messages` list/create and like/unlike.
- `/team-messages/unread-count`.
- `/me/push-token`, `/me/push-badge/reset`.

Excluded
- External notification provider infrastructure details.
- Email-based invitation messaging.

## 4. Actors
- Admin
Permissions: send/read team messages in scope.
Actions: post announcements and interact with conversations.
Restrictions: scope-bound.
- Coach
Permissions: same as admin for managed teams.
Actions: announcements and direct messages to players.
Restrictions: cannot access unmanaged team conversations.
- Parent
Permissions: read team announcements, direct context via linked player.
Actions: consume conversation/messages.
Restrictions: no out-of-scope team access.
- Player
Permissions: read team announcements and own coach conversation.
Actions: send/receive direct conversation messages.
Restrictions: no other player conversations.
- Guest
Permissions: none.
Actions: none.
Restrictions: blocked.
- Unauthenticated user
Permissions: none.
Actions: none.
Restrictions: blocked.
- System
Permissions: resolve conversation ids, unread counts, read markers.
Actions: persist message/reaction records and badge state.
Restrictions: must enforce team/player relation checks.

## 5. Entry Points
- UI: messages pages/views and periodic unread polling.
- Routes: messaging endpoints + push token endpoints.
- System triggers: unread count updates and badge reset events.

## 6. User Flows
- Main flow: open messages -> list conversations -> open thread -> send message.
- Variants: post team announcement; like/unlike team message.
- Back navigation: return from conversation to list.
- Interruptions: team scope missing or forbidden.
- Errors: invalid conversation id, forbidden team.
- Edge cases: linked player absent for parent/player role.

## 7. Functional Behavior
- UI behavior: list/team feed and unread badge updates.
- Actions: create messages, toggle reactions, fetch unread count.
- States: unread/read, liked/unliked.
- Conditions: team context resolution by role and linked player.
- Validations: conversation id parsing and team access checks.
- Blocking rules: forbidden when user lacks readable team scope.
- Automations: unread count recomputed from read markers.

## 8. Data Model
- `TeamMessage`
Source: team feed composer.
Purpose: broadcast messages.
Format: content + author + team scope.
Constraints: indexed by team/time.
- `DirectMessage`
Source: conversation composer.
Purpose: coach-player thread.
Format: content + sender + player/team context.
Constraints: indexed by team/player/time.
- `TeamMessageRead`, `TeamMessageLike`, `PushDevice`, `User.pushBadgeCount`
Source: read/like/push actions.
Purpose: notification state.
Format: relation records and counters.
Constraints: unique like/read composites.

## 9. Business Rules
- Conversation ids encode `announcements` or `coach` scope.
- Parent/player conversation access depends on linked player.
- Unread count uses per-team read timestamp comparison.
- Push token endpoint stores device-token mapping for user.

## 10. State Machine
- Message states: created, visible, deleted (if supported).
- Reaction states: liked/unliked.
- Read states: unread/read by team and user.
- Badge states: incremented (inferred) and reset via endpoint.
- Invalid transitions: send message to forbidden conversation.

## 11. UI Components
- Conversation list.
- Message thread view.
- Team feed with like controls.
- Notification badge indicators.

## 12. Routes / API / Handlers
- `/messages/conversations`, `/messages/conversations/:id/messages`.
- `/team-messages`, `/team-messages/unread-count`.
- `/team-messages/:id/reactions/like`.
- `/me/push-token`, `/me/push-badge/reset`.

## 13. Persistence
- Models: `TeamMessage`, `DirectMessage`, `TeamMessageLike`, `TeamMessageRead`, `PushDevice`, `User`.
- Relations: message-author, message-team, player-sender context.
- Constraints: unique like and read markers.
- Lifecycle: reads/likes update per-user message state.

## 14. Dependencies
- Upstream: auth, scope resolution, player linkage.
- Downstream: web/iOS badges and message tabs.
- Cross-repo: both clients consume unread count and conversation APIs.

## 15. Error Handling
- Validation: malformed conversation id rejected.
- Missing data: unknown conversation/player yields errors.
- Permissions: forbidden team access returns 403.
- Broken states: missing linked player for parent role.
- Current vs expected: error contracts should be standardized for conversation parsing failures.

## 16. Security
- Access control: strict team/player relationship checks.
- Data exposure: only scoped conversations and messages.
- Guest rules: blocked.

## 17. UX Requirements
- Feedback: instant send and like state feedback.
- Errors: clear messaging when access is denied.
- Empty states: no conversations/messages.
- Loading: incremental message loading if volume grows.

## 18. Ambiguities & Gaps
- Observed
- Conversation ID scheme is string-encoded in server logic.
- Inferred
- No generic conversation table; IDs are deterministic virtual identifiers.
- Missing
- Formal documented schema for conversation id grammar.
- Tech debt
- Messaging rules are tightly coupled to server route logic.

## 19. Recommendations
- Product: publish messaging permission matrix per role.
- UX: add explicit read markers in clients.
- Tech: move conversation-id parser into shared tested module.
- Security: add throttling for message send endpoints.

## 20. Acceptance Criteria
1. Scoped users can list and read allowed conversations.
2. Sending message persists and appears in thread.
3. Like/unlike updates counters deterministically.
4. Push token and badge reset endpoints work for authenticated user.

## 21. Test Scenarios
- Happy path: coach sends conversation message to player context.
- Permissions: user cannot read foreign team conversation.
- Errors: invalid conversation id format.
- Edge cases: unread count when no `TeamMessageRead` record exists.

## 22. Technical References
- `src/server.ts`
- `prisma/schema.prisma`
