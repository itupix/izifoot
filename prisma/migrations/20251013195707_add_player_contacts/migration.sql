/*
  Warnings:

  - A unique constraint covering the columns `[email]` on the table `Player` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "Player" ADD COLUMN "email" TEXT;
ALTER TABLE "Player" ADD COLUMN "phone" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "Player_email_key" ON "Player"("email");
