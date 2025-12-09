import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  const email = process.env.DEFAULT_ADMIN_EMAIL || 'admin@example.com';
  const password = process.env.DEFAULT_ADMIN_PASSWORD || 'changeme123';
  const name = process.env.DEFAULT_ADMIN_NAME || 'Default Admin';

  if (!password || password.length < 8) {
    throw new Error('DEFAULT_ADMIN_PASSWORD must be at least 8 characters long');
  }

  const existing = await prisma.agent.findUnique({ where: { email } });

  const passwordHash = await bcrypt.hash(password, 10);

  if (existing) {
    const updated = await prisma.agent.update({
      where: { id: existing.id },
      data: {
        password: passwordHash,
        name,
        displayName: existing.displayName || name,
        isAdmin: true,
      },
    });
    console.log(`Updated existing admin agent: ${updated.email}`);
  } else {
    const created = await prisma.agent.create({
      data: {
        email,
        password: passwordHash,
        name,
        displayName: name,
        isAdmin: true,
        status: 'ONLINE',
      },
    });
    console.log(`Created default admin agent: ${created.email}`);
  }
}

main()
  .catch((err) => {
    console.error('Seed admin failed:', err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
