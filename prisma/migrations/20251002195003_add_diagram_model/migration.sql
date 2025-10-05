-- CreateTable
CREATE TABLE "Diagram" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "title" TEXT NOT NULL,
    "data" TEXT NOT NULL,
    "drillId" TEXT,
    "trainingDrillId" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- CreateIndex
CREATE INDEX "Diagram_drillId_idx" ON "Diagram"("drillId");

-- CreateIndex
CREATE INDEX "Diagram_trainingDrillId_idx" ON "Diagram"("trainingDrillId");
