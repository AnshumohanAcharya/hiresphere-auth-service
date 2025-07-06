import { SetMetadata } from '@nestjs/common';
import { RateLimitOptions } from '../guards/redis-rate-limit.guard';

export const RATE_LIMIT_KEY = 'rateLimit';

export const RateLimit = (options: RateLimitOptions) =>
  SetMetadata(RATE_LIMIT_KEY, options);

export const RateLimits = {
  // Predefined rate limit configurations
  // Strict rate limiting for sensitive operations
  STRICT: {
    limit: 5,
    windowMs: 15 * 60 * 1000, // 15 minutes
    keyPrefix: 'strict',
  },

  // Standard rate limiting for most endpoints
  STANDARD: {
    limit: 100,
    windowMs: 15 * 60 * 1000, // 15 minutes
    keyPrefix: 'standard',
  },

  // Relaxed rate limiting for public endpoints
  RELAXED: {
    limit: 1000,
    windowMs: 15 * 60 * 1000, // 15 minutes
    keyPrefix: 'relaxed',
  },

  // OTP-specific rate limiting
  OTP: {
    limit: 3,
    windowMs: 5 * 60 * 1000, // 5 minutes
    keyPrefix: 'otp',
  },

  // Login-specific rate limiting
  LOGIN: {
    limit: 5,
    windowMs: 15 * 60 * 1000, // 15 minutes
    keyPrefix: 'login',
  },

  // Registration-specific rate limiting
  REGISTRATION: {
    limit: 3,
    windowMs: 60 * 60 * 1000, // 1 hour
    keyPrefix: 'registration',
  },
};
