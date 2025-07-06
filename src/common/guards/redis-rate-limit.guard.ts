import { Request } from 'express';
import { Reflector } from '@nestjs/core';
import { RedisService } from '../../redis/redis.service';
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
} from '@nestjs/common';

// Define proper interfaces
export interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  message?: string;
  statusCode?: number;
}

interface RequestWithUser extends Request {
  user?: {
    id: string;
    email: string;
    isActive: boolean;
  };
}

@Injectable()
export class RedisRateLimitGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly redisService: RedisService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const rateLimitOptions = this.reflector.get<RateLimitOptions>(
      'rateLimit',
      context.getHandler(),
    );

    if (!rateLimitOptions) {
      return true;
    }

    const request = context.switchToHttp().getRequest<RequestWithUser>();

    // Get IP address with proper typing
    const ip =
      request.socket?.remoteAddress ||
      (request.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      'unknown';

    const key = `rate_limit:${ip}`;
    const now = Date.now();
    const windowMs = rateLimitOptions.windowMs;
    const maxRequests = rateLimitOptions.maxRequests;

    try {
      // Use the existing checkRateLimit method from RedisService
      const rateLimitData = await this.redisService.checkRateLimit(
        key,
        maxRequests,
        windowMs,
      );

      if (rateLimitData.blocked) {
        const retryAfter = rateLimitData.blockExpiresAt
          ? Math.ceil((rateLimitData.blockExpiresAt - now) / 1000)
          : Math.ceil((rateLimitData.resetTime - now) / 1000);

        throw new HttpException(
          {
            message: rateLimitOptions.message || 'Rate limit exceeded',
            retryAfter,
            resetTime: new Date(rateLimitData.resetTime).toISOString(),
          },
          rateLimitOptions.statusCode || HttpStatus.TOO_MANY_REQUESTS,
        );
      }

      return true;
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      // If Redis error, allow request (fail open)
      console.error('Rate limit Redis error:', error);
      return true;
    }
  }
}
