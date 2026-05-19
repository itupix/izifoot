CREATE TYPE "MobileAuthPlatform" AS ENUM ('IOS');

CREATE TABLE "MobileAuthCode" (
    "id" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "stateHash" TEXT NOT NULL,
    "platform" "MobileAuthPlatform" NOT NULL,
    "userId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MobileAuthCode_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "MobileAuthCode_codeHash_key" ON "MobileAuthCode"("codeHash");
CREATE INDEX "MobileAuthCode_stateHash_idx" ON "MobileAuthCode"("stateHash");
CREATE INDEX "MobileAuthCode_userId_createdAt_idx" ON "MobileAuthCode"("userId", "createdAt" DESC);

ALTER TABLE "MobileAuthCode"
ADD CONSTRAINT "MobileAuthCode_userId_fkey"
FOREIGN KEY ("userId") REFERENCES "User"("id")
ON DELETE CASCADE
ON UPDATE CASCADE;
