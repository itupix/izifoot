ALTER TABLE "Player"
ADD COLUMN "is_active" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN "deactivated_at" TIMESTAMP(3);

CREATE INDEX "Player_teamId_is_active_idx" ON "Player"("teamId", "is_active");
