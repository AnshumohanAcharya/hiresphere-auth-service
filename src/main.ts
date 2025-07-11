import * as compression from 'compression';
import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import helmet from 'helmet';

import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

/**
 * HireSphere Authentication Service - Main Application Entry Point
 *
 * This file bootstraps the NestJS application with comprehensive security middleware,
 * rate limiting, compression, CORS, validation, and API documentation.
 *
 * Security Features:
 * - Helmet for security headers
 * - Rate limiting to prevent abuse
 * - Slow down mechanism for progressive throttling
 * - CORS configuration for cross-origin requests
 * - Global validation pipe for request sanitization
 *
 * @author HireSphere Team
 * @version 1.0.0
 */

/**
 * Bootstrap the NestJS application with security and performance optimizations
 *
 * Steps:
 * 1. Create NestJS application instance
 * 2. Apply security middleware (Helmet, Rate Limiting, Slow Down)
 * 3. Configure compression and CORS
 * 4. Set up global validation pipe
 * 5. Configure Swagger API documentation
 * 6. Start the server
 */
async function bootstrap() {
  // Step 1: Create NestJS application instance
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  // Step 2: Security Middleware Configuration

  // Helmet: Security headers for protection against common vulnerabilities
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", 'data:', 'https:'],
        },
      },
      crossOriginEmbedderPolicy: false, // Disabled for API compatibility
    }),
  );

  // Compression: Reduce response size for better performance
  app.use(compression());

  // Rate Limiting: Prevent abuse by limiting requests per IP
  const limiter = rateLimit({
    windowMs: configService.get('RATE_LIMIT_WINDOW', 900000), // 15 minutes
    max: configService.get('RATE_LIMIT_MAX_REQUESTS', 100), // 100 requests per window
    message: {
      error: 'Too many requests from this IP, please try again later.',
      retryAfter: Math.ceil(
        configService.get('RATE_LIMIT_WINDOW', 900000) / 1000,
      ),
    },
    standardHeaders: true, // Return rate limit info in headers
    legacyHeaders: false,
  });

  // Slow Down: Progressive throttling for high-frequency requests
  const speedLimiter = slowDown({
    windowMs: configService.get('SLOW_DOWN_WINDOW', 900000), // 15 minutes
    delayAfter: configService.get('SLOW_DOWN_DELAY_AFTER', 50), // Allow 50 requests, then slow down
    delayMs: (hits) =>
      Math.min(hits * 100, configService.get('SLOW_DOWN_MAX_DELAY', 20000)), // Progressive delay
  });

  // Apply rate limiting middleware
  app.use(limiter);
  app.use(speedLimiter);

  // Step 3: CORS Configuration
  app.enableCors({
    origin: configService.get('FRONTEND_URL', 'http://localhost:3000'),
    credentials: true, // Allow cookies and authentication headers
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  // Step 4: Global Configuration
  // API prefix for versioning (only for REST endpoints)
  app.setGlobalPrefix(configService.get('API_PREFIX', 'api/v1'), {
    exclude: ['/graphql', '/health'],
  });

  // Global validation pipe for request sanitization and transformation
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Strip properties not defined in DTOs
      forbidNonWhitelisted: true, // Throw error for non-whitelisted properties
      transform: true, // Transform payloads to DTO instances
      transformOptions: {
        enableImplicitConversion: true, // Convert string to numbers, etc.
      },
    }),
  );

  // Step 5: Swagger API Documentation
  const config = new DocumentBuilder()
    .setTitle('HireSphere Auth Service')
    .setDescription(
      'Secure authentication API for HireSphere with comprehensive security features',
    )
    .setVersion('1.0')
    .addBearerAuth() // JWT authentication documentation
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  // Step 6: Start the server
  const port = configService.get<number>('PORT', 4000);
  await app.listen(port);

  // Application startup information
  console.log(`🚀 Application is running on: http://localhost:${port}`);
  console.log(`🔒 Health Check: http://localhost:${port}/health`);
  console.log(`📚 API Documentation: http://localhost:${port}/docs`);
  console.log(`🔮 GraphQL Playground: http://localhost:${port}/graphql`);
  console.log(
    `🔐 Environment: ${configService.get('NODE_ENV', 'development')}`,
  );
}

// Start the application
bootstrap().catch((error) => {
  console.error('❌ Failed to start application:', error);
  process.exit(1);
});

/**
 * Sample Usage:
 *
 * 1. Start the application:
 *    npm run start:dev
 *
 * 2. Access endpoints:
 *    - Health Check: GET /api/v1/health
 *    - Register: POST /api/v1/auth/register
 *    - Login: POST /api/v1/auth/login
 *    - Verify OTP: POST /api/v1/auth/verify-otp
 *
 * 3. View API documentation:
 *    - Swagger UI: http://localhost:3000/docs
 *
 * 4. Environment Configuration:
 *    - Copy .env.example to .env
 *    - Configure database, Redis, email, and JWT secrets
 *    - Set NODE_ENV for production/development
 */
