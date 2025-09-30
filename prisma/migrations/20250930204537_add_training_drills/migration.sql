-- CreateTable
CREATE TABLE "TrainingDrill" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "trainingId" TEXT NOT NULL,
    "drillId" TEXT NOT NULL,
    "order" INTEGER NOT NULL DEFAULT 0,
    "duration" INTEGER,
    "notes" TEXT,
    CONSTRAINT "TrainingDrill_trainingId_fkey" FOREIGN KEY ("trainingId") REFERENCES "Training" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateIndex
CREATE INDEX "TrainingDrill_trainingId_idx" ON "TrainingDrill"("trainingId");
