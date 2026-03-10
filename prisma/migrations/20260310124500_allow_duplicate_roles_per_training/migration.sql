DROP INDEX IF EXISTS "TrainingRoleAssignment_trainingId_role_key";

CREATE INDEX IF NOT EXISTS "TrainingRoleAssignment_trainingId_role_idx"
  ON "TrainingRoleAssignment"("trainingId", "role");
