import { EncryptionService } from './encryption.service';
import { SecurityService } from './security.service';
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { APP_GUARD, Reflector } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { RedisRateLimitGuard } from '../common/guards/redis-rate-limit.guard';
import { RedisService } from '../redis/redis.service';

@Module({
  imports: [
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get('JWT_EXPIRES_IN', '15m'),
        },
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [
    SecurityService,
    EncryptionService,
    {
      provide: APP_GUARD,
      useFactory: (
        configService: ConfigService,
        reflector: Reflector,
        redisService: RedisService,
      ) => {
        const isDevelopment = configService.get('NODE_ENV') === 'development';
        return isDevelopment
          ? null
          : new RedisRateLimitGuard(reflector, redisService);
      },
      inject: [ConfigService, Reflector, RedisService],
    },
  ],
  exports: [SecurityService, EncryptionService],
})
export class SecurityModule {}
