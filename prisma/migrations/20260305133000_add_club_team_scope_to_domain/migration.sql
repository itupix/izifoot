-- Add club/team scope to domain tables

ALTER TABLE "Player" ADD COLUMN IF NOT EXISTS "clubId" TEXT;
ALTER TABLE "Player" ADD COLUMN IF NOT EXISTS "teamId" TEXT;

ALTER TABLE "Training" ADD COLUMN IF NOT EXISTS "clubId" TEXT;
ALTER TABLE "Training" ADD COLUMN IF NOT EXISTS "teamId" TEXT;

ALTER TABLE "Plateau" ADD COLUMN IF NOT EXISTS "clubId" TEXT;
ALTER TABLE "Plateau" ADD COLUMN IF NOT EXISTS "teamId" TEXT;

ALTER TABLE "Attendance" ADD COLUMN IF NOT EXISTS "clubId" TEXT;
ALTER TABLE "Attendance" ADD COLUMN IF NOT EXISTS "teamId" TEXT;

ALTER TABLE "Match" ADD COLUMN IF NOT EXISTS "clubId" TEXT;
ALTER TABLE "Match" ADD COLUMN IF NOT EXISTS "teamId" TEXT;

ALTER TABLE "TrainingDrill" ADD COLUMN IF NOT EXISTS "clubId" TEXT;
ALTER TABLE "TrainingDrill" ADD COLUMN IF NOT EXISTS "teamId" TEXT;

ALTER TABLE "Drill" ADD COLUMN IF NOT EXISTS "clubId" TEXT;
ALTER TABLE "Drill" ADD COLUMN IF NOT EXISTS "teamId" TEXT;

ALTER TABLE "Diagram" ADD COLUMN IF NOT EXISTS "clubId" TEXT;
ALTER TABLE "Diagram" ADD COLUMN IF NOT EXISTS "teamId" TEXT;

CREATE INDEX IF NOT EXISTS "Player_clubId_teamId_idx" ON "Player"("clubId", "teamId");
CREATE INDEX IF NOT EXISTS "Training_clubId_teamId_idx" ON "Training"("clubId", "teamId");
CREATE INDEX IF NOT EXISTS "Plateau_clubId_teamId_idx" ON "Plateau"("clubId", "teamId");
CREATE INDEX IF NOT EXISTS "Attendance_clubId_teamId_idx" ON "Attendance"("clubId", "teamId");
CREATE INDEX IF NOT EXISTS "Match_clubId_teamId_idx" ON "Match"("clubId", "teamId");
CREATE INDEX IF NOT EXISTS "TrainingDrill_clubId_teamId_idx" ON "TrainingDrill"("clubId", "teamId");
CREATE INDEX IF NOT EXISTS "Drill_clubId_teamId_idx" ON "Drill"("clubId", "teamId");
CREATE INDEX IF NOT EXISTS "Diagram_clubId_teamId_idx" ON "Diagram"("clubId", "teamId");
