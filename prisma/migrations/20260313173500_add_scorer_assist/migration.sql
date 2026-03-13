ALTER TABLE "Scorer"
ADD COLUMN IF NOT EXISTS "assistId" TEXT;

CREATE INDEX IF NOT EXISTS "Scorer_assistId_idx" ON "Scorer"("assistId");

DO $$ BEGIN
  ALTER TABLE "Scorer"
    ADD CONSTRAINT "Scorer_assistId_fkey"
    FOREIGN KEY ("assistId") REFERENCES "Player"("id")
    ON DELETE SET NULL ON UPDATE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;
