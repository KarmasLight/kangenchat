-- CreateEnum
CREATE TYPE "AgentRole" AS ENUM ('ADMIN', 'MANAGER', 'AGENT');

-- AlterTable: add role column with default AGENT
ALTER TABLE "Agent"
  ADD COLUMN "role" "AgentRole" NOT NULL DEFAULT 'AGENT';

-- Backfill data: promote existing admins
UPDATE "Agent" SET "role" = 'ADMIN' WHERE "isAdmin" IS TRUE;

-- Drop obsolete boolean column
ALTER TABLE "Agent" DROP COLUMN "isAdmin";
