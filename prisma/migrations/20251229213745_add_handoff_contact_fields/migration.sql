-- AlterTable
ALTER TABLE "ChatSession" ADD COLUMN     "contactPhone" TEXT,
ADD COLUMN     "distributorId" TEXT,
ADD COLUMN     "handoffInfoProvidedAt" TIMESTAMP(3),
ADD COLUMN     "handoffInfoRequestedAt" TIMESTAMP(3);
