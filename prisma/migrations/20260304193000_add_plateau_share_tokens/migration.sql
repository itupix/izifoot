CREATE TABLE IF NOT EXISTS "PlateauShareToken" (
    "id" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "plateauId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PlateauShareToken_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "PlateauShareToken_token_key" ON "PlateauShareToken"("token");
CREATE INDEX IF NOT EXISTS "PlateauShareToken_plateauId_idx" ON "PlateauShareToken"("plateauId");

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'PlateauShareToken_plateauId_fkey'
    ) THEN
        ALTER TABLE "PlateauShareToken"
        ADD CONSTRAINT "PlateauShareToken_plateauId_fkey"
        FOREIGN KEY ("plateauId") REFERENCES "Plateau"("id")
        ON DELETE CASCADE ON UPDATE CASCADE;
    END IF;
END $$;
