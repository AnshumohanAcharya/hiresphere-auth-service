import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { AuditLogInterceptor } from './common/interceptors/audit-log.interceptor';
import { DatabaseModule } from './database/database.module';
import { EmailModule } from './email/email.module';
import { GraphQLModule as NestGraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { GraphQLModule } from './graphql/graphql.module';
import { RedisModule } from './redis/redis.module';
import { SecurityModule } from './security/security.module';
import { UsersModule } from './users/users.module';
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { ThrottlerModule } from '@nestjs/throttler';

/**
 * HireSphere Authentication Service - Root Application Module
 *
 * This is the root module that configures all application dependencies,
 * global interceptors, and module imports. It serves as the entry point
 * for the entire application architecture.
 *
 * Module Structure:
 * - ConfigModule: Environment configuration
 * - ThrottlerModule: Built-in rate limiting
 * - DatabaseModule: Prisma database connection
 * - RedisModule: Redis cache and session management
 * - AuthModule: Authentication and authorization
 * - UsersModule: User management operations
 * - EmailModule: Email sending capabilities
 * - SecurityModule: Security utilities and OTP management
 *
 * Global Features:
 * - Audit logging interceptor for all requests
 * - Environment-based configuration
 * - Rate limiting protection
 *
 * @author HireSphere Team
 * @version 1.0.0
 */

@Module({
  imports: [
    // Global Configuration Module
    ConfigModule.forRoot({
      isGlobal: true, // Make config available throughout the app
      envFilePath: '.env', // Load environment variables from .env file
    }),

    // Built-in Rate Limiting (additional to express-rate-limit)
    ThrottlerModule.forRoot([
      {
        ttl: 60000, // 1 minute window
        limit: 10, // 10 requests per minute per IP
      },
    ]),

    // GraphQL Configuration
    NestGraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: true, // Automatically generate schema from TypeScript classes
      playground: true, // Enable GraphQL Playground in development
      introspection: true, // Enable introspection for GraphQL Playground
      context: ({ req }) => ({ req }), // Pass request context to resolvers
      formatError: (error) => {
        // Custom error formatting
        const originalError = error.extensions?.originalError as any;
        if (originalError) {
          return {
            message: originalError.message,
            statusCode: originalError.statusCode,
            error: originalError.error,
          };
        }
        return error;
      },
    }),

    // Core Infrastructure Modules
    DatabaseModule, // Prisma database connection and service
    RedisModule, // Redis cache and session management

    // Feature Modules
    AuthModule, // Authentication, authorization, and JWT management
    UsersModule, // User CRUD operations and profile management
    EmailModule, // Email sending with templates
    SecurityModule, // Security utilities, OTP, and password validation
    GraphQLModule, // GraphQL resolvers and types
  ],
  controllers: [AppController], // Root controller for health checks and metrics
  providers: [
    AppService, // Root service for basic operations

    // Global Interceptor: Audit logging for all requests
    {
      provide: APP_INTERCEPTOR,
      useClass: AuditLogInterceptor, // Logs all requests with IP, user-agent, etc.
    },
  ],
})
/**
 * Module Dependencies Flow:
 *
 * 1. ConfigModule (Global)
 *    ↓ Provides environment variables to all modules
 *
 * 2. DatabaseModule
 *    ↓ Provides PrismaService to UsersModule, SecurityModule
 *
 * 3. RedisModule
 *    ↓ Provides RedisService to AuthModule, SecurityModule
 *
 * 4. SecurityModule
 *    ↓ Provides security utilities to AuthModule, UsersModule
 *
 * 5. EmailModule
 *    ↓ Provides email sending to AuthModule
 *
 * 6. UsersModule
 *    ↓ Provides user operations to AuthModule
 *
 * 7. AuthModule
 *    ↓ Provides authentication to AppController
 *
 * Sample Usage:
 *
 * 1. Import in other modules:
 *    import { AppModule } from './app.module';
 *
 * 2. Access global services:
 *    constructor(private configService: ConfigService) {}
 *
 * 3. Use audit logging (automatic):
 *    All HTTP requests are automatically logged with IP, user-agent, etc.
 *
 * 4. Environment configuration:
 *    - Copy .env.example to .env
 *    - Configure all required environment variables
 *    - Restart application to apply changes
 */
export class AppModule {}
