-- CreateEnum
CREATE TYPE "AgentStatus" AS ENUM ('ONLINE', 'OFFLINE');

-- AlterTable
ALTER TABLE "Agent" ADD COLUMN     "avatarUrl" TEXT,
ADD COLUMN     "displayName" TEXT,
ADD COLUMN     "phone" TEXT,
ADD COLUMN     "status" "AgentStatus" NOT NULL DEFAULT 'ONLINE';
