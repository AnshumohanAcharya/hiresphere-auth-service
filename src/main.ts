import * as compression from 'compression';
import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import helmet from 'helmet';
import * as express from 'express';

import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Security middleware
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
      crossOriginEmbedderPolicy: false,
    }),
  );

  app.use(compression());

  // Rate limiting
  const isDevelopment = configService.get('NODE_ENV') === 'development';
  const enableRateLimit = configService.get(
    'ENABLE_RATE_LIMIT',
    !isDevelopment,
  );

  if (enableRateLimit) {
    const limiter = rateLimit({
      windowMs: configService.get('RATE_LIMIT_WINDOW', 900000),
      max: configService.get('RATE_LIMIT_MAX_REQUESTS', 100),
      message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: Math.ceil(
          configService.get('RATE_LIMIT_WINDOW', 900000) / 1000,
        ),
      },
      standardHeaders: true,
      legacyHeaders: false,
    });

    const speedLimiter = slowDown({
      windowMs: configService.get('SLOW_DOWN_WINDOW', 900000),
      delayAfter: configService.get('SLOW_DOWN_DELAY_AFTER', 50),
      delayMs: (hits) =>
        Math.min(hits * 100, configService.get('SLOW_DOWN_MAX_DELAY', 20000)),
    });

    app.use(limiter);
    app.use(speedLimiter);
  }

  // CORS configuration
  app.enableCors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  // Global configuration
  app.setGlobalPrefix(configService.get('API_PREFIX', 'api/v1'), {
    exclude: ['/graphql', '/health'],
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // Swagger documentation
  const config = new DocumentBuilder()
    .setTitle('HireSphere Auth Service')
    .setDescription(
      'Secure authentication API for HireSphere with comprehensive security features',
    )
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  const port = configService.get<number>('PORT', 4000);
  await app.listen(port);

  console.log(`🚀 Application is running on: http://localhost:${port}`);
  console.log(`🔒 Health Check: http://localhost:${port}/health`);
  console.log(`📚 API Documentation: http://localhost:${port}/docs`);
  console.log(`🔮 GraphQL Playground: http://localhost:${port}/graphql`);
  console.log(
    `🔐 Environment: ${configService.get('NODE_ENV', 'development')}`,
  );
}

bootstrap().catch((error) => {
  console.error('❌ Failed to start application:', error);
  process.exit(1);
});
