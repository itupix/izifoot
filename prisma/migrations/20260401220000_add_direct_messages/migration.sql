CREATE TABLE "DirectMessage" (
  "id" TEXT NOT NULL,
  "clubId" TEXT NOT NULL,
  "teamId" TEXT NOT NULL,
  "playerId" TEXT NOT NULL,
  "senderUserId" TEXT NOT NULL,
  "content" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "DirectMessage_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "DirectMessage_clubId_teamId_createdAt_idx" ON "DirectMessage"("clubId", "teamId", "createdAt" DESC);
CREATE INDEX "DirectMessage_teamId_playerId_createdAt_idx" ON "DirectMessage"("teamId", "playerId", "createdAt" DESC);
CREATE INDEX "DirectMessage_playerId_createdAt_idx" ON "DirectMessage"("playerId", "createdAt" DESC);

ALTER TABLE "DirectMessage"
ADD CONSTRAINT "DirectMessage_senderUserId_fkey"
FOREIGN KEY ("senderUserId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "DirectMessage"
ADD CONSTRAINT "DirectMessage_playerId_fkey"
FOREIGN KEY ("playerId") REFERENCES "Player"("id") ON DELETE CASCADE ON UPDATE CASCADE;
