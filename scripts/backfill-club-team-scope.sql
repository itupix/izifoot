-- Backfill club/team scope on legacy rows.
-- Target: PostgreSQL (Railway compatible)
-- Safe to re-run: updates only rows with missing scope.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =========================
-- 1) PRE-CHECK (read-only)
-- =========================

SELECT 'User missing clubId' AS check_name, COUNT(*) AS row_count
FROM "User"
WHERE "clubId" IS NULL
UNION ALL
SELECT 'Player missing scope', COUNT(*) FROM "Player" WHERE "clubId" IS NULL OR "teamId" IS NULL
UNION ALL
SELECT 'Training missing scope', COUNT(*) FROM "Training" WHERE "clubId" IS NULL OR "teamId" IS NULL
UNION ALL
SELECT 'Plateau missing scope', COUNT(*) FROM "Plateau" WHERE "clubId" IS NULL OR "teamId" IS NULL
UNION ALL
SELECT 'Match missing scope', COUNT(*) FROM "Match" WHERE "clubId" IS NULL OR "teamId" IS NULL
UNION ALL
SELECT 'Attendance missing scope', COUNT(*) FROM "Attendance" WHERE "clubId" IS NULL OR "teamId" IS NULL
UNION ALL
SELECT 'TrainingDrill missing scope', COUNT(*) FROM "TrainingDrill" WHERE "clubId" IS NULL OR "teamId" IS NULL
UNION ALL
SELECT 'Drill missing scope', COUNT(*) FROM "Drill" WHERE "clubId" IS NULL OR "teamId" IS NULL
UNION ALL
SELECT 'Diagram missing scope', COUNT(*) FROM "Diagram" WHERE "clubId" IS NULL OR "teamId" IS NULL
;

-- =================================
-- 2) APPLY BACKFILL (write section)
-- =================================

BEGIN;

-- A) Ensure each DIRECTION has a club (create one if missing).
WITH need_club AS (
  SELECT u."id", u."email"
  FROM "User" u
  WHERE u."role" = 'DIRECTION'
    AND u."clubId" IS NULL
),
created AS (
  INSERT INTO "Club" ("id", "name", "createdAt")
  SELECT
    'club_' || REPLACE(gen_random_uuid()::text, '-', ''),
    'Club ' || split_part(nc."email", '@', 1),
    NOW()
  FROM need_club nc
  RETURNING "id", "name", "createdAt"
),
paired AS (
  SELECT
    nc."id" AS "userId",
    c."id" AS "clubId",
    ROW_NUMBER() OVER (ORDER BY nc."id") AS rn_nc,
    ROW_NUMBER() OVER (ORDER BY c."createdAt", c."id") AS rn_c
  FROM need_club nc
  JOIN created c ON TRUE
)
UPDATE "User" u
SET "clubId" = p."clubId"
FROM paired p
WHERE u."id" = p."userId"
  AND p.rn_nc = p.rn_c
;

-- B) Direction-created users without club inherit creator club if possible (fallback: oldest direction club).
-- If you have explicit inviter data later, replace this heuristic.
UPDATE "User" u
SET "clubId" = fallback."clubId"
FROM (
  SELECT u2."id" AS "userId",
         (
           SELECT d."clubId"
           FROM "User" d
           WHERE d."role" = 'DIRECTION' AND d."clubId" IS NOT NULL
           ORDER BY d."createdAt" ASC
           LIMIT 1
         ) AS "clubId"
  FROM "User" u2
  WHERE u2."clubId" IS NULL
) fallback
WHERE u."id" = fallback."userId"
  AND fallback."clubId" IS NOT NULL
;

-- C) PLAYER team from account; PARENT inherits linked player's team.
UPDATE "User" u
SET "teamId" = p."teamId"
FROM "User" p
WHERE u."role" = 'PARENT'
  AND u."teamId" IS NULL
  AND u."linkedPlayerUserId" = p."id"
  AND p."teamId" IS NOT NULL
;

-- D) Backfill Player from owner user.
UPDATE "Player" p
SET
  "clubId" = COALESCE(p."clubId", u."clubId"),
  "teamId" = COALESCE(p."teamId", u."teamId")
FROM "User" u
WHERE p."userId" = u."id"
  AND (p."clubId" IS NULL OR p."teamId" IS NULL)
;

-- E) Training / Plateau / Drill / Diagram / TrainingDrill / Match from owner user first.
UPDATE "Training" t
SET
  "clubId" = COALESCE(t."clubId", u."clubId"),
  "teamId" = COALESCE(t."teamId", u."teamId")
FROM "User" u
WHERE t."userId" = u."id"
  AND (t."clubId" IS NULL OR t."teamId" IS NULL)
;

UPDATE "Plateau" p
SET
  "clubId" = COALESCE(p."clubId", u."clubId"),
  "teamId" = COALESCE(p."teamId", u."teamId")
FROM "User" u
WHERE p."userId" = u."id"
  AND (p."clubId" IS NULL OR p."teamId" IS NULL)
;

UPDATE "Drill" d
SET
  "clubId" = COALESCE(d."clubId", u."clubId"),
  "teamId" = COALESCE(d."teamId", u."teamId")
FROM "User" u
WHERE d."userId" = u."id"
  AND (d."clubId" IS NULL OR d."teamId" IS NULL)
;

UPDATE "Diagram" d
SET
  "clubId" = COALESCE(d."clubId", u."clubId"),
  "teamId" = COALESCE(d."teamId", u."teamId")
FROM "User" u
WHERE d."userId" = u."id"
  AND (d."clubId" IS NULL OR d."teamId" IS NULL)
;

UPDATE "TrainingDrill" td
SET
  "clubId" = COALESCE(td."clubId", u."clubId"),
  "teamId" = COALESCE(td."teamId", u."teamId")
FROM "User" u
WHERE td."userId" = u."id"
  AND (td."clubId" IS NULL OR td."teamId" IS NULL)
;

UPDATE "Match" m
SET
  "clubId" = COALESCE(m."clubId", u."clubId"),
  "teamId" = COALESCE(m."teamId", u."teamId")
FROM "User" u
WHERE m."userId" = u."id"
  AND (m."clubId" IS NULL OR m."teamId" IS NULL)
;

-- F) Relational enrichment: match/team from plateau.
UPDATE "Match" m
SET
  "clubId" = COALESCE(m."clubId", p."clubId"),
  "teamId" = COALESCE(m."teamId", p."teamId")
FROM "Plateau" p
WHERE m."plateauId" = p."id"
  AND (m."clubId" IS NULL OR m."teamId" IS NULL)
;

-- G) TrainingDrill from training.
UPDATE "TrainingDrill" td
SET
  "clubId" = COALESCE(td."clubId", t."clubId"),
  "teamId" = COALESCE(td."teamId", t."teamId")
FROM "Training" t
WHERE td."trainingId" = t."id"
  AND (td."clubId" IS NULL OR td."teamId" IS NULL)
;

-- H) Diagram from trainingDrill, then from drill.
UPDATE "Diagram" d
SET
  "clubId" = COALESCE(d."clubId", td."clubId"),
  "teamId" = COALESCE(d."teamId", td."teamId")
FROM "TrainingDrill" td
WHERE d."trainingDrillId" = td."id"
  AND (d."clubId" IS NULL OR d."teamId" IS NULL)
;

UPDATE "Diagram" d
SET
  "clubId" = COALESCE(d."clubId", dr."clubId"),
  "teamId" = COALESCE(d."teamId", dr."teamId")
FROM "Drill" dr
WHERE d."drillId" = dr."id"
  AND (d."clubId" IS NULL OR d."teamId" IS NULL)
;

-- I) Attendance from owner user first.
UPDATE "Attendance" a
SET
  "clubId" = COALESCE(a."clubId", u."clubId"),
  "teamId" = COALESCE(a."teamId", u."teamId")
FROM "User" u
WHERE a."userId" = u."id"
  AND (a."clubId" IS NULL OR a."teamId" IS NULL)
;

-- J) Attendance from training / plateau / player in that order.
UPDATE "Attendance" a
SET
  "clubId" = COALESCE(a."clubId", t."clubId"),
  "teamId" = COALESCE(a."teamId", t."teamId")
FROM "Training" t
WHERE a."trainingId" = t."id"
  AND (a."clubId" IS NULL OR a."teamId" IS NULL)
;

UPDATE "Attendance" a
SET
  "clubId" = COALESCE(a."clubId", p."clubId"),
  "teamId" = COALESCE(a."teamId", p."teamId")
FROM "Plateau" p
WHERE a."plateauId" = p."id"
  AND (a."clubId" IS NULL OR a."teamId" IS NULL)
;

UPDATE "Attendance" a
SET
  "clubId" = COALESCE(a."clubId", pl."clubId"),
  "teamId" = COALESCE(a."teamId", pl."teamId")
FROM "Player" pl
WHERE a."playerId" = pl."id"
  AND (a."clubId" IS NULL OR a."teamId" IS NULL)
;

COMMIT;

-- ==========================
-- 3) POST-CHECK (read-only)
-- ==========================

SELECT 'User missing clubId' AS check_name, COUNT(*) AS row_count
FROM "User"
WHERE "clubId" IS NULL
UNION ALL
SELECT 'Player missing scope', COUNT(*) FROM "Player" WHERE "clubId" IS NULL OR "teamId" IS NULL
UNION ALL
SELECT 'Training missing scope', COUNT(*) FROM "Training" WHERE "clubId" IS NULL OR "teamId" IS NULL
UNION ALL
SELECT 'Plateau missing scope', COUNT(*) FROM "Plateau" WHERE "clubId" IS NULL OR "teamId" IS NULL
UNION ALL
SELECT 'Match missing scope', COUNT(*) FROM "Match" WHERE "clubId" IS NULL OR "teamId" IS NULL
UNION ALL
SELECT 'Attendance missing scope', COUNT(*) FROM "Attendance" WHERE "clubId" IS NULL OR "teamId" IS NULL
UNION ALL
SELECT 'TrainingDrill missing scope', COUNT(*) FROM "TrainingDrill" WHERE "clubId" IS NULL OR "teamId" IS NULL
UNION ALL
SELECT 'Drill missing scope', COUNT(*) FROM "Drill" WHERE "clubId" IS NULL OR "teamId" IS NULL
UNION ALL
SELECT 'Diagram missing scope', COUNT(*) FROM "Diagram" WHERE "clubId" IS NULL OR "teamId" IS NULL
;
