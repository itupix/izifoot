-- CreateTable
CREATE TABLE "Drill" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "title" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "duration" INTEGER NOT NULL,
    "players" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "tags" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Drill_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Drill_userId_idx" ON "Drill"("userId");

-- AddForeignKey
ALTER TABLE "Drill"
ADD CONSTRAINT "Drill_userId_fkey"
FOREIGN KEY ("userId") REFERENCES "User"("id")
ON DELETE SET NULL ON UPDATE CASCADE;
