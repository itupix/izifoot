CREATE TABLE "TeamMessage" (
  "id" TEXT NOT NULL,
  "clubId" TEXT NOT NULL,
  "teamId" TEXT NOT NULL,
  "authorUserId" TEXT NOT NULL,
  "content" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "TeamMessage_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "TeamMessageLike" (
  "id" TEXT NOT NULL,
  "messageId" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "TeamMessageLike_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "TeamMessageRead" (
  "id" TEXT NOT NULL,
  "teamId" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "lastReadAt" TIMESTAMP(3) NOT NULL,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "TeamMessageRead_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "TeamMessage_teamId_createdAt_idx"
  ON "TeamMessage"("teamId", "createdAt" DESC);

CREATE INDEX "TeamMessage_clubId_teamId_createdAt_idx"
  ON "TeamMessage"("clubId", "teamId", "createdAt" DESC);

CREATE UNIQUE INDEX "TeamMessageLike_messageId_userId_key"
  ON "TeamMessageLike"("messageId", "userId");

CREATE INDEX "TeamMessageLike_userId_createdAt_idx"
  ON "TeamMessageLike"("userId", "createdAt" DESC);

CREATE UNIQUE INDEX "TeamMessageRead_teamId_userId_key"
  ON "TeamMessageRead"("teamId", "userId");

CREATE INDEX "TeamMessageRead_userId_teamId_idx"
  ON "TeamMessageRead"("userId", "teamId");

ALTER TABLE "TeamMessage"
  ADD CONSTRAINT "TeamMessage_teamId_fkey"
  FOREIGN KEY ("teamId") REFERENCES "Team"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "TeamMessage"
  ADD CONSTRAINT "TeamMessage_authorUserId_fkey"
  FOREIGN KEY ("authorUserId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "TeamMessageLike"
  ADD CONSTRAINT "TeamMessageLike_messageId_fkey"
  FOREIGN KEY ("messageId") REFERENCES "TeamMessage"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "TeamMessageLike"
  ADD CONSTRAINT "TeamMessageLike_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "TeamMessageRead"
  ADD CONSTRAINT "TeamMessageRead_teamId_fkey"
  FOREIGN KEY ("teamId") REFERENCES "Team"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "TeamMessageRead"
  ADD CONSTRAINT "TeamMessageRead_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
