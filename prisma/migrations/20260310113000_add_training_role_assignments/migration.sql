CREATE TABLE IF NOT EXISTS "TrainingRoleAssignment" (
  "id" TEXT NOT NULL,
  "userId" TEXT,
  "clubId" TEXT,
  "teamId" TEXT,
  "trainingId" TEXT NOT NULL,
  "role" TEXT NOT NULL,
  "playerId" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "TrainingRoleAssignment_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "TrainingRoleAssignment_trainingId_role_key"
  ON "TrainingRoleAssignment"("trainingId", "role");

CREATE UNIQUE INDEX IF NOT EXISTS "TrainingRoleAssignment_trainingId_playerId_key"
  ON "TrainingRoleAssignment"("trainingId", "playerId");

CREATE INDEX IF NOT EXISTS "TrainingRoleAssignment_trainingId_idx"
  ON "TrainingRoleAssignment"("trainingId");

CREATE INDEX IF NOT EXISTS "TrainingRoleAssignment_userId_trainingId_idx"
  ON "TrainingRoleAssignment"("userId", "trainingId");

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'TrainingRoleAssignment_userId_fkey'
  ) THEN
    ALTER TABLE "TrainingRoleAssignment"
      ADD CONSTRAINT "TrainingRoleAssignment_userId_fkey"
      FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'TrainingRoleAssignment_trainingId_fkey'
  ) THEN
    ALTER TABLE "TrainingRoleAssignment"
      ADD CONSTRAINT "TrainingRoleAssignment_trainingId_fkey"
      FOREIGN KEY ("trainingId") REFERENCES "Training"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'TrainingRoleAssignment_playerId_fkey'
  ) THEN
    ALTER TABLE "TrainingRoleAssignment"
      ADD CONSTRAINT "TrainingRoleAssignment_playerId_fkey"
      FOREIGN KEY ("playerId") REFERENCES "Player"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
  END IF;
END $$;
