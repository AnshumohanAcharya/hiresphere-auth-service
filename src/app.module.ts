import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { GraphQLModule as NestGraphQLModule } from '@nestjs/graphql';
import { ThrottlerModule } from '@nestjs/throttler';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { AuditLogInterceptor } from './common/interceptors/audit-log.interceptor';
import { DatabaseModule } from './database/database.module';
import { EmailModule } from './email/email.module';
import { GraphQLModule } from './graphql/graphql.module';
import { RedisModule } from './redis/redis.module';
import { SecurityModule } from './security/security.module';
import { UsersModule } from './users/users.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),

    ThrottlerModule.forRoot([
      {
        ttl: 60000,
        limit: 10,
      },
    ]),

    NestGraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: true,
      playground: process.env.NODE_ENV === 'development',
      introspection: process.env.NODE_ENV === 'development',
      context: ({ req }) => ({ req }),
      path: '/graphql',
      csrfPrevention: false,
    }),

    DatabaseModule,
    RedisModule,
    AuthModule,
    UsersModule,
    EmailModule,
    SecurityModule,
    GraphQLModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_INTERCEPTOR,
      useClass: AuditLogInterceptor,
    },
  ],
})
export class AppModule {}

/**
 * Sample Usage for Centralized Services:
 *
 * 1. RedisService (Global):
 *    constructor(private redisService: RedisService) {}
 *    await this.redisService.setOtp(key, otpData, 300);
 *    const otp = await this.redisService.getOtp(key);
 *
 * 2. SecurityService:
 *    constructor(private securityService: SecurityService) {}
 *    const otp = await this.securityService.generateAndStoreOtp(userId, OtpType.EMAIL_VERIFICATION);
 *    const result = await this.securityService.verifyOtp(userId, code, OtpType.EMAIL_VERIFICATION);
 *
 * 3. EmailService:
 *    constructor(private emailService: EmailService) {}
 *    await this.emailService.sendOtpEmail(email, name, otp, 'EMAIL_VERIFICATION');
 *
 * 4. PrismaService (Global):
 *    constructor(private prisma: PrismaService) {}
 *    const user = await this.prisma.user.findUnique({ where: { id } });
 *
 * 5. AuditLogInterceptor (Global):
 *    Automatically logs all HTTP/GraphQL requests with IP, user-agent, and response data
 */
