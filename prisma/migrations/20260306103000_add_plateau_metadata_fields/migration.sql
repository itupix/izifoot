-- Add optional location/schedule metadata to plateaus.
-- Backfill is implicitly NULL for existing rows.

ALTER TABLE "Plateau"
  ADD COLUMN IF NOT EXISTS "address" TEXT,
  ADD COLUMN IF NOT EXISTS "start_time" VARCHAR(5),
  ADD COLUMN IF NOT EXISTS "meeting_time" VARCHAR(5);
