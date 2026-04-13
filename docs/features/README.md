# Backend Feature Index

Repository role: API contract owner and business-logic authority for Izifoot.

## Coverage Method
- Source scanned: `src/server.ts`, `src/*.ts`, `prisma/schema.prisma`, migrations.
- Feature status labels: `existing`, `partial`, `broken`, `to-build`, `unclear`.
- Every feature file separates `Observed`, `Inferred`, `Missing`, and `Tech debt`.

## Feature Files
- `auth-and-session-management.md`
- `authorization-and-team-scoping.md`
- `club-team-and-account-administration.md`
- `player-roster-and-parent-linking.md`
- `training-lifecycle-attendance-and-roles.md`
- `matchday-and-match-operations.md`
- `drills-diagrams-ai-and-tactics.md`
- `messaging-and-push-notifications.md`
- `planning-sharing-public-access-and-player-portal.md`

## Cross-Repo Contract Notes
- Backend is the source of truth for payload shape, role rules, and error model.
- Web and iOS must consume only documented endpoints from backend feature files.
