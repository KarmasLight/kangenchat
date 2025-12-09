-- AlterTable
ALTER TABLE "ChatSession" ADD COLUMN     "offlineHandledAt" TIMESTAMP(3),
ADD COLUMN     "offlineHandledById" TEXT;

-- AddForeignKey
ALTER TABLE "ChatSession" ADD CONSTRAINT "ChatSession_offlineHandledById_fkey" FOREIGN KEY ("offlineHandledById") REFERENCES "Agent"("id") ON DELETE SET NULL ON UPDATE CASCADE;
