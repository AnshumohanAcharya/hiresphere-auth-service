import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seeding...');

  // Clean up existing data
  await prisma.auditLog.deleteMany();
  await prisma.user.deleteMany();

  console.log('✅ Database cleaned');

  // Create a test user with properly hashed password
  const hashedPassword = await bcrypt.hash('TestPassword123!', 12);
  const testUser = await prisma.user.create({
    data: {
      email: 'test@hiresphere.com',
      firstName: 'Test',
      lastName: 'User',
      password: hashedPassword,
      isEmailVerified: true,
      isActive: true,
    },
  });

  console.log('✅ Test user created:', testUser.email);

  // Create some audit logs
  await prisma.auditLog.createMany({
    data: [
      {
        userId: testUser.id,
        action: 'USER_REGISTERED',
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Test Browser)',
        details: {
          email: testUser.email,
          firstName: testUser.firstName,
          lastName: testUser.lastName,
        },
      },
      {
        userId: testUser.id,
        action: 'LOGIN_SUCCESS',
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Test Browser)',
        details: { email: testUser.email },
      },
    ],
  });

  console.log('✅ Audit logs created');

  console.log('🎉 Database seeding completed!');
}

main()
  .catch((e) => {
    console.error('❌ Error during seeding:', e);
    process.exit(1);
  })
  .finally(() => {
    prisma.$disconnect();
  });
