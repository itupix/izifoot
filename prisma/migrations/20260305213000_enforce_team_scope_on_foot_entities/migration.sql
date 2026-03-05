-- Enforce team scope for core foot entities.
-- Targets: Player, Training, Plateau, Drill

BEGIN;

-- Pre-fill active team for existing staff accounts when the value is unambiguous.
UPDATE "User" u
SET "teamId" = u."managedTeamIds"[1]
WHERE u."role" = 'COACH'
  AND u."teamId" IS NULL
  AND array_length(u."managedTeamIds", 1) = 1;

UPDATE "User" u
SET "teamId" = t."id"
FROM (
  SELECT "clubId", MIN("id") AS "id"
  FROM "Team"
  GROUP BY "clubId"
  HAVING COUNT(*) = 1
) t
WHERE u."role" = 'DIRECTION'
  AND u."teamId" IS NULL
  AND u."clubId" = t."clubId";

-- Backfill from owner user when possible.
UPDATE "Player" p
SET "teamId" = u."teamId"
FROM "User" u
WHERE p."teamId" IS NULL
  AND p."userId" = u."id"
  AND u."teamId" IS NOT NULL;

UPDATE "Training" t
SET "teamId" = u."teamId"
FROM "User" u
WHERE t."teamId" IS NULL
  AND t."userId" = u."id"
  AND u."teamId" IS NOT NULL;

UPDATE "Plateau" p
SET "teamId" = u."teamId"
FROM "User" u
WHERE p."teamId" IS NULL
  AND p."userId" = u."id"
  AND u."teamId" IS NOT NULL;

UPDATE "Drill" d
SET "teamId" = u."teamId"
FROM "User" u
WHERE d."teamId" IS NULL
  AND d."userId" = u."id"
  AND u."teamId" IS NOT NULL;

-- Additional relational backfills.
UPDATE "Drill" d
SET "teamId" = td."teamId"
FROM "TrainingDrill" td
WHERE d."teamId" IS NULL
  AND td."drillId" = d."id"
  AND td."teamId" IS NOT NULL;

UPDATE "Training" t
SET "teamId" = td."teamId"
FROM "TrainingDrill" td
WHERE t."teamId" IS NULL
  AND td."trainingId" = t."id"
  AND td."teamId" IS NOT NULL;

UPDATE "Player" p
SET "teamId" = a."teamId"
FROM "Attendance" a
WHERE p."teamId" IS NULL
  AND a."playerId" = p."id"
  AND a."teamId" IS NOT NULL;

UPDATE "Plateau" p
SET "teamId" = m."teamId"
FROM "Match" m
WHERE p."teamId" IS NULL
  AND m."plateauId" = p."id"
  AND m."teamId" IS NOT NULL;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM "Player" WHERE "teamId" IS NULL) THEN
    RAISE EXCEPTION 'Cannot enforce NOT NULL on Player.teamId: unresolved rows remain';
  END IF;
  IF EXISTS (SELECT 1 FROM "Training" WHERE "teamId" IS NULL) THEN
    RAISE EXCEPTION 'Cannot enforce NOT NULL on Training.teamId: unresolved rows remain';
  END IF;
  IF EXISTS (SELECT 1 FROM "Plateau" WHERE "teamId" IS NULL) THEN
    RAISE EXCEPTION 'Cannot enforce NOT NULL on Plateau.teamId: unresolved rows remain';
  END IF;
  IF EXISTS (SELECT 1 FROM "Drill" WHERE "teamId" IS NULL) THEN
    RAISE EXCEPTION 'Cannot enforce NOT NULL on Drill.teamId: unresolved rows remain';
  END IF;
END $$;

ALTER TABLE "Player" ALTER COLUMN "teamId" SET NOT NULL;
ALTER TABLE "Training" ALTER COLUMN "teamId" SET NOT NULL;
ALTER TABLE "Plateau" ALTER COLUMN "teamId" SET NOT NULL;
ALTER TABLE "Drill" ALTER COLUMN "teamId" SET NOT NULL;

DO $$ BEGIN
  ALTER TABLE "Player"
    ADD CONSTRAINT "Player_teamId_fkey"
    FOREIGN KEY ("teamId") REFERENCES "Team"("id")
    ON DELETE RESTRICT ON UPDATE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  ALTER TABLE "Training"
    ADD CONSTRAINT "Training_teamId_fkey"
    FOREIGN KEY ("teamId") REFERENCES "Team"("id")
    ON DELETE RESTRICT ON UPDATE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  ALTER TABLE "Plateau"
    ADD CONSTRAINT "Plateau_teamId_fkey"
    FOREIGN KEY ("teamId") REFERENCES "Team"("id")
    ON DELETE RESTRICT ON UPDATE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  ALTER TABLE "Drill"
    ADD CONSTRAINT "Drill_teamId_fkey"
    FOREIGN KEY ("teamId") REFERENCES "Team"("id")
    ON DELETE RESTRICT ON UPDATE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

COMMIT;
