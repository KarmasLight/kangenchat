-- AlterTable
ALTER TABLE "ChatSession" ADD COLUMN     "initialEmailRequestedAt" TIMESTAMP(3),
ADD COLUMN     "initialPhoneRequestedAt" TIMESTAMP(3),
ADD COLUMN     "transferEnabled" BOOLEAN NOT NULL DEFAULT true;

-- AlterTable
ALTER TABLE "Message" ADD COLUMN     "issueType" TEXT,
ADD COLUMN     "visitorId" TEXT;

-- AlterTable
ALTER TABLE "Visitor" ADD COLUMN     "phone" TEXT;

-- AddForeignKey
ALTER TABLE "Message" ADD CONSTRAINT "Message_visitorId_fkey" FOREIGN KEY ("visitorId") REFERENCES "Visitor"("id") ON DELETE SET NULL ON UPDATE CASCADE;
