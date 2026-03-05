-- Account invitation flow (direction invites, invited user sets password)

DO $$ BEGIN
  CREATE TYPE "AccountInviteStatus" AS ENUM ('PENDING', 'ACCEPTED', 'CANCELLED', 'EXPIRED');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS "AccountInvite" (
  "id" TEXT NOT NULL,
  "token" TEXT NOT NULL,
  "email" TEXT NOT NULL,
  "role" "UserRole" NOT NULL,
  "status" "AccountInviteStatus" NOT NULL DEFAULT 'PENDING',
  "clubId" TEXT NOT NULL,
  "invitedByUserId" TEXT NOT NULL,
  "teamId" TEXT,
  "managedTeamIds" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  "linkedPlayerUserId" TEXT,
  "userId" TEXT,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "acceptedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "AccountInvite_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "AccountInvite_token_key" ON "AccountInvite"("token");
CREATE UNIQUE INDEX IF NOT EXISTS "AccountInvite_userId_key" ON "AccountInvite"("userId");
CREATE INDEX IF NOT EXISTS "AccountInvite_clubId_status_idx" ON "AccountInvite"("clubId", "status");
CREATE INDEX IF NOT EXISTS "AccountInvite_email_status_idx" ON "AccountInvite"("email", "status");

DO $$ BEGIN
  ALTER TABLE "AccountInvite"
    ADD CONSTRAINT "AccountInvite_invitedByUserId_fkey"
    FOREIGN KEY ("invitedByUserId") REFERENCES "User"("id")
    ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  ALTER TABLE "AccountInvite"
    ADD CONSTRAINT "AccountInvite_userId_fkey"
    FOREIGN KEY ("userId") REFERENCES "User"("id")
    ON DELETE SET NULL ON UPDATE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;
