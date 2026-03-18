ALTER TABLE "AccountInvite"
  ADD COLUMN IF NOT EXISTS "linkedPlayerId" TEXT;

CREATE INDEX IF NOT EXISTS "AccountInvite_clubId_linkedPlayerId_status_idx"
  ON "AccountInvite"("clubId", "linkedPlayerId", "status");
