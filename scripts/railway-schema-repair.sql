-- PostgreSQL schema repair for legacy Railway databases.
-- This aligns the production schema with the current Prisma schema
-- for all fields currently handled by the compatibility layer.

BEGIN;

-- Player
ALTER TABLE "Player" ADD COLUMN IF NOT EXISTS "userId" TEXT;
ALTER TABLE "Player" ADD COLUMN IF NOT EXISTS "email" TEXT;
ALTER TABLE "Player" ADD COLUMN IF NOT EXISTS "phone" TEXT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'Player_userId_fkey'
  ) THEN
    ALTER TABLE "Player"
      ADD CONSTRAINT "Player_userId_fkey"
      FOREIGN KEY ("userId") REFERENCES "User"("id")
      ON DELETE SET NULL
      ON UPDATE CASCADE;
  END IF;
END $$;

DROP INDEX IF EXISTS "Player_email_key";
CREATE UNIQUE INDEX IF NOT EXISTS "Player_userId_email_key" ON "Player"("userId", "email");

-- Training
ALTER TABLE "Training" ADD COLUMN IF NOT EXISTS "userId" TEXT;
ALTER TABLE "Training" ADD COLUMN IF NOT EXISTS "status" TEXT NOT NULL DEFAULT 'PLANNED';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'Training_userId_fkey'
  ) THEN
    ALTER TABLE "Training"
      ADD CONSTRAINT "Training_userId_fkey"
      FOREIGN KEY ("userId") REFERENCES "User"("id")
      ON DELETE SET NULL
      ON UPDATE CASCADE;
  END IF;
END $$;

-- Plateau
ALTER TABLE "Plateau" ADD COLUMN IF NOT EXISTS "userId" TEXT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'Plateau_userId_fkey'
  ) THEN
    ALTER TABLE "Plateau"
      ADD CONSTRAINT "Plateau_userId_fkey"
      FOREIGN KEY ("userId") REFERENCES "User"("id")
      ON DELETE SET NULL
      ON UPDATE CASCADE;
  END IF;
END $$;

-- Attendance
ALTER TABLE "Attendance" ADD COLUMN IF NOT EXISTS "userId" TEXT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'Attendance_userId_fkey'
  ) THEN
    ALTER TABLE "Attendance"
      ADD CONSTRAINT "Attendance_userId_fkey"
      FOREIGN KEY ("userId") REFERENCES "User"("id")
      ON DELETE SET NULL
      ON UPDATE CASCADE;
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS "Attendance_userId_session_type_session_id_playerId_key"
  ON "Attendance"("userId", "session_type", "session_id", "playerId");

-- Match
ALTER TABLE "Match" ADD COLUMN IF NOT EXISTS "userId" TEXT;
ALTER TABLE "Match" ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMP(3);
ALTER TABLE "Match" ADD COLUMN IF NOT EXISTS "opponentName" TEXT;

UPDATE "Match"
SET "updatedAt" = COALESCE("updatedAt", "createdAt", CURRENT_TIMESTAMP)
WHERE "updatedAt" IS NULL;

ALTER TABLE "Match" ALTER COLUMN "updatedAt" SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'Match_userId_fkey'
  ) THEN
    ALTER TABLE "Match"
      ADD CONSTRAINT "Match_userId_fkey"
      FOREIGN KEY ("userId") REFERENCES "User"("id")
      ON DELETE SET NULL
      ON UPDATE CASCADE;
  END IF;
END $$;

-- TrainingDrill
ALTER TABLE "TrainingDrill" ADD COLUMN IF NOT EXISTS "userId" TEXT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'TrainingDrill_userId_fkey'
  ) THEN
    ALTER TABLE "TrainingDrill"
      ADD CONSTRAINT "TrainingDrill_userId_fkey"
      FOREIGN KEY ("userId") REFERENCES "User"("id")
      ON DELETE SET NULL
      ON UPDATE CASCADE;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS "TrainingDrill_userId_trainingId_idx"
  ON "TrainingDrill"("userId", "trainingId");

-- Diagram
ALTER TABLE "Diagram" ADD COLUMN IF NOT EXISTS "userId" TEXT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'Diagram_userId_fkey'
  ) THEN
    ALTER TABLE "Diagram"
      ADD CONSTRAINT "Diagram_userId_fkey"
      FOREIGN KEY ("userId") REFERENCES "User"("id")
      ON DELETE SET NULL
      ON UPDATE CASCADE;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS "Diagram_userId_drillId_idx"
  ON "Diagram"("userId", "drillId");

CREATE INDEX IF NOT EXISTS "Diagram_userId_trainingDrillId_idx"
  ON "Diagram"("userId", "trainingDrillId");

COMMIT;
