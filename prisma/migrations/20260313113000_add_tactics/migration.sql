-- Create tactic storage for team tactical boards
CREATE TABLE "Tactic" (
  "id" TEXT NOT NULL,
  "teamId" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "formation" TEXT NOT NULL,
  "points" JSONB NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "Tactic_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "Tactic_teamId_idx" ON "Tactic"("teamId");
CREATE INDEX "Tactic_teamId_updatedAt_idx" ON "Tactic"("teamId", "updatedAt" DESC);
CREATE UNIQUE INDEX "Tactic_teamId_name_lower_key" ON "Tactic"("teamId", lower("name"));

ALTER TABLE "Tactic"
  ADD CONSTRAINT "Tactic_teamId_fkey"
  FOREIGN KEY ("teamId") REFERENCES "Team"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

-- Keep updatedAt in sync on UPDATE, like Prisma @updatedAt behavior.
CREATE OR REPLACE FUNCTION set_tactic_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW."updatedAt" = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tactic_set_updated_at
BEFORE UPDATE ON "Tactic"
FOR EACH ROW
EXECUTE FUNCTION set_tactic_updated_at();
