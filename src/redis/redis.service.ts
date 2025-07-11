import Redis, { RedisOptions } from 'ioredis';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { OtpType } from '@prisma/client';

export interface OtpData {
  code: string; // The actual OTP code (6 digits)
  attempts: number; // Number of verification attempts
  expiresAt: number; // Expiration timestamp
  type: OtpType; // Type of OTP (EMAIL_VERIFICATION, PASSWORD_RESET)
  userId: string; // Associated user ID
}

export interface RateLimitData {
  count: number; // Current request count
  resetTime: number; // When the rate limit window resets
  blocked: boolean; // Whether the IP/user is currently blocked
  blockExpiresAt?: number; // When the block expires (if blocked)
}

export interface RefreshTokenData {
  userId: string; // Associated user ID
  deviceInfo?: string; // Device type (Mobile, Desktop, etc.)
  ipAddress?: string; // IP address where token was created
  userAgent?: string; // User agent string
  createdAt: number; // Token creation timestamp
  expiresAt: number; // Token expiration timestamp
}

@Injectable()
export class RedisService {
  private readonly logger = new Logger(RedisService.name);
  private readonly client: Redis;

  constructor(private configService: ConfigService) {
    // Initialize Redis connection
    const redisUrl = this.configService.get<string>('REDIS_URL');

    let config: RedisOptions;

    if (redisUrl) {
      // Use REDIS_URL if provided (recommended for cloud Redis like Upstash)
      config = {
        lazyConnect: true,
        maxRetriesPerRequest: 3,
        enableReadyCheck: false,
      };

      // Create Redis client with URL
      this.client = new Redis(redisUrl, config);
    } else {
      // Fallback to individual parameters
      config = {
        host: this.configService.get<string>('REDIS_HOST', 'localhost'),
        port: this.configService.get<number>('REDIS_PORT', 6379),
        password: this.configService.get<string>('REDIS_PASSWORD'),
        db: this.configService.get<number>('REDIS_DB', 0),
        lazyConnect: true,
        maxRetriesPerRequest: 3,
        enableReadyCheck: false,
      };

      this.client = new Redis(config);
    }

    // Set up event listeners for connection monitoring
    this.client.on('error', (err) => this.logger.error('Redis error', err));
    this.client.on('connect', () => this.logger.log('Connected to Redis'));
    this.client.on('ready', () => this.logger.log('Redis is ready'));
    this.client.on('close', () => this.logger.warn('Redis connection closed'));
    this.client.on('reconnecting', () =>
      this.logger.log('Redis reconnecting...'),
    );
  }

  // ============================================================================
  // OTP MANAGEMENT
  // ============================================================================

  /**
   * Store OTP data in Redis with automatic expiration
   *
   * @param key - Redis key for the OTP
   * @param otpData - OTP data to store
   * @param ttl - Time to live in seconds
   *
   * @example
   * await redisService.setOtp('otp:user123:EMAIL_VERIFICATION', {
   *   code: '123456',
   *   attempts: 0,
   *   expiresAt: Date.now() + 300000,
   *   type: OtpType.EMAIL_VERIFICATION,
   *   userId: 'user123'
   * }, 300);
   */
  async setOtp(key: string, otpData: OtpData, ttl: number): Promise<void> {
    try {
      await this.client.set(key, JSON.stringify(otpData), 'EX', ttl);
      this.logger.debug(`OTP stored for key: ${key}`);
    } catch (error) {
      this.logger.error(`Failed to store OTP for key: ${key}`, error);
      throw error;
    }
  }

  /**
   * Retrieve OTP data from Redis
   *
   * @param key - Redis key for the OTP
   * @returns OTP data or null if not found
   *
   * @example
   * const otpData = await redisService.getOtp('otp:user123:EMAIL_VERIFICATION');
   * if (otpData && otpData.code === '123456') {
   *   // OTP is valid
   * }
   */
  async getOtp(key: string): Promise<OtpData | null> {
    try {
      const data = await this.client.get(key);
      return data ? (JSON.parse(data) as OtpData) : null;
    } catch (error) {
      this.logger.error(`Failed to get OTP for key: ${key}`, error);
      return null;
    }
  }

  /**
   * Delete OTP data from Redis (used after successful verification)
   *
   * @param key - Redis key for the OTP
   *
   * @example
   * await redisService.deleteOtp('otp:user123:EMAIL_VERIFICATION');
   */
  async deleteOtp(key: string): Promise<void> {
    try {
      await this.client.del(key);
      this.logger.debug(`OTP deleted for key: ${key}`);
    } catch (error) {
      this.logger.error(`Failed to delete OTP for key: ${key}`, error);
    }
  }

  /**
   * Increment OTP verification attempts and update the stored data
   *
   * @param key - Redis key for the OTP
   * @returns Updated number of attempts
   *
   * @example
   * const attempts = await redisService.incrementOtpAttempts('otp:user123:EMAIL_VERIFICATION');
   * if (attempts >= 3) {
   *   // Block further attempts
   * }
   */
  async incrementOtpAttempts(key: string): Promise<number> {
    try {
      const otpData = await this.getOtp(key);
      if (!otpData) return 0;

      otpData.attempts += 1;
      await this.setOtp(key, otpData, this.getOtpTtl());
      return otpData.attempts;
    } catch (error) {
      this.logger.error(
        `Failed to increment OTP attempts for key: ${key}`,
        error,
      );
      return 0;
    }
  }

  // ============================================================================
  // RATE LIMITING
  // ============================================================================

  /**
   * Check and update rate limiting for a given key
   * Implements progressive blocking based on excess attempts
   *
   * @param key - Rate limit key (usually IP or user ID)
   * @param limit - Maximum allowed requests in the window
   * @param windowMs - Time window in milliseconds
   * @returns Rate limit data with current state
   *
   * @example
   * const rateLimitData = await redisService.checkRateLimit('rate_limit:login:192.168.1.1', 5, 900000);
   * if (rateLimitData.blocked) {
   *   throw new Error('Too many requests, please try again later');
   * }
   */
  async checkRateLimit(
    key: string,
    limit: number,
    windowMs: number,
  ): Promise<RateLimitData> {
    try {
      const rateLimitDataStr = await this.client.get(key);
      const now = Date.now();

      // If no existing data, create new rate limit entry
      if (!rateLimitDataStr) {
        const newData: RateLimitData = {
          count: 1,
          resetTime: now + windowMs,
          blocked: false,
        };
        await this.client.set(
          key,
          JSON.stringify(newData),
          'EX',
          Math.ceil(windowMs / 1000),
        );
        return newData;
      }

      const rateLimitData: RateLimitData = JSON.parse(
        rateLimitDataStr,
      ) as RateLimitData;

      // Check if rate limit window has reset
      if (now > rateLimitData.resetTime) {
        const newData: RateLimitData = {
          count: 1,
          resetTime: now + windowMs,
          blocked: false,
        };
        await this.client.set(
          key,
          JSON.stringify(newData),
          'EX',
          Math.ceil(windowMs / 1000),
        );
        return newData;
      }

      // Check if currently blocked
      if (
        rateLimitData.blocked &&
        rateLimitData.blockExpiresAt &&
        now < rateLimitData.blockExpiresAt
      ) {
        return rateLimitData;
      }

      // Increment request count
      rateLimitData.count += 1;

      // Check if limit exceeded and apply progressive blocking
      if (rateLimitData.count > limit) {
        const blockDuration = this.getBlockDuration(
          rateLimitData.count - limit,
        );
        rateLimitData.blocked = true;
        rateLimitData.blockExpiresAt = now + blockDuration;
        await this.client.set(
          key,
          JSON.stringify(rateLimitData),
          'EX',
          Math.ceil(blockDuration / 1000),
        );
      } else {
        await this.client.set(
          key,
          JSON.stringify(rateLimitData),
          'EX',
          Math.ceil((rateLimitData.resetTime - now) / 1000),
        );
      }

      return rateLimitData;
    } catch (error) {
      this.logger.error(`Failed to check rate limit for key: ${key}`, error);
      return { count: 0, resetTime: Date.now(), blocked: false };
    }
  }

  // ============================================================================
  // SESSION MANAGEMENT
  // ============================================================================

  /**
   * Store session data in Redis
   *
   * @param key - Session key
   * @param data - Session data to store
   * @param ttl - Time to live in seconds
   *
   * @example
   * await redisService.setSession('session:user123', {
   *   userId: 'user123',
   *   lastActivity: Date.now()
   * }, 3600);
   */
  async setSession(key: string, data: any, ttl: number): Promise<void> {
    try {
      await this.client.set(key, JSON.stringify(data), 'EX', ttl);
    } catch (error) {
      this.logger.error(`Failed to set session for key: ${key}`, error);
      throw error;
    }
  }

  /**
   * Retrieve session data from Redis
   *
   * @param key - Session key
   * @returns Session data or null if not found
   *
   * @example
   * const session = await redisService.getSession('session:user123');
   * if (session) {
   *   // Session is valid
   * }
   */
  async getSession(key: string): Promise<unknown> {
    try {
      const data = await this.client.get(key);
      return data ? JSON.parse(data) : null;
    } catch (error) {
      this.logger.error(`Failed to get session for key: ${key}`, error);
      return null;
    }
  }

  /**
   * Delete session data from Redis
   *
   * @param key - Session key
   *
   * @example
   * await redisService.deleteSession('session:user123');
   */
  async deleteSession(key: string): Promise<void> {
    try {
      await this.client.del(key);
    } catch (error) {
      this.logger.error(`Failed to delete session for key: ${key}`, error);
    }
  }

  // ============================================================================
  // SECURITY FEATURES
  // ============================================================================

  /**
   * Store failed login attempts for an identifier (IP or user ID)
   *
   * @param key - Failed login attempts key
   * @param attempts - Number of failed attempts
   * @param ttl - Time to live in seconds
   *
   * @example
   * await redisService.setFailedLoginAttempts('failed_login:192.168.1.1', 3, 900);
   */
  async setFailedLoginAttempts(
    key: string,
    attempts: number,
    ttl: number,
  ): Promise<void> {
    try {
      await this.client.set(key, attempts.toString(), 'EX', ttl);
    } catch (error) {
      this.logger.error(
        `Failed to set failed login attempts for key: ${key}`,
        error,
      );
    }
  }

  /**
   * Get current failed login attempts for an identifier
   *
   * @param key - Failed login attempts key
   * @returns Number of failed attempts
   *
   * @example
   * const attempts = await redisService.getFailedLoginAttempts('failed_login:192.168.1.1');
   * if (attempts >= 5) {
   *   // Account should be locked
   * }
   */
  async getFailedLoginAttempts(key: string): Promise<number> {
    try {
      const attempts = await this.client.get(key);
      return attempts ? parseInt(attempts) : 0;
    } catch (error) {
      this.logger.error(
        `Failed to get failed login attempts for key: ${key}`,
        error,
      );
      return 0;
    }
  }

  /**
   * Increment failed login attempts and store the updated count
   *
   * @param key - Failed login attempts key
   * @param ttl - Time to live in seconds
   * @returns Updated number of failed attempts
   *
   * @example
   * const attempts = await redisService.incrementFailedLoginAttempts('failed_login:192.168.1.1', 900);
   * if (attempts >= 5) {
   *   await lockAccount(userId);
   * }
   */
  async incrementFailedLoginAttempts(
    key: string,
    ttl: number,
  ): Promise<number> {
    try {
      const attempts = await this.getFailedLoginAttempts(key);
      const newAttempts = attempts + 1;
      await this.setFailedLoginAttempts(key, newAttempts, ttl);
      return newAttempts;
    } catch (error) {
      this.logger.error(
        `Failed to increment failed login attempts for key: ${key}`,
        error,
      );
      return 0;
    }
  }

  /**
   * Reset failed login attempts for an identifier (used after successful login)
   *
   * @param key - Failed login attempts key
   *
   * @example
   * await redisService.resetFailedLoginAttempts('failed_login:192.168.1.1');
   */
  async resetFailedLoginAttempts(key: string): Promise<void> {
    try {
      await this.client.del(key);
    } catch (error) {
      this.logger.error(
        `Failed to reset failed login attempts for key: ${key}`,
        error,
      );
    }
  }

  // ============================================================================
  // REFRESH TOKEN MANAGEMENT
  // ============================================================================

  /**
   * Store refresh token data with device and security information
   *
   * @param tokenId - Unique token identifier
   * @param tokenData - Refresh token data with device info
   * @param ttl - Time to live in seconds
   *
   * @example
   * await redisService.setRefreshToken('token123', {
   *   userId: 'user123',
   *   deviceInfo: 'Mobile',
   *   ipAddress: '192.168.1.1',
   *   userAgent: 'Mozilla/5.0...',
   *   createdAt: Date.now(),
   *   expiresAt: Date.now() + 604800000
   * }, 604800);
   */
  async setRefreshToken(
    tokenId: string,
    tokenData: RefreshTokenData,
    ttl: number,
  ): Promise<void> {
    try {
      await this.client.set(tokenId, JSON.stringify(tokenData), 'EX', ttl);
      this.logger.debug(`Refresh token stored for user: ${tokenData.userId}`);
    } catch (error) {
      this.logger.error(
        `Failed to store refresh token for user: ${tokenData.userId}`,
        error,
      );
      throw error;
    }
  }

  /**
   * Retrieve refresh token data
   *
   * @param tokenId - Unique token identifier
   * @returns Refresh token data or null if not found
   *
   * @example
   * const tokenData = await redisService.getRefreshToken('token123');
   * if (tokenData && tokenData.expiresAt > Date.now()) {
   *   // Token is valid
   * }
   */
  async getRefreshToken(tokenId: string): Promise<RefreshTokenData | null> {
    try {
      const data = await this.client.get(tokenId);
      return data ? (JSON.parse(data) as RefreshTokenData) : null;
    } catch (error) {
      this.logger.error(`Failed to get refresh token: ${tokenId}`, error);
      return null;
    }
  }

  /**
   * Delete a specific refresh token (used for logout or token revocation)
   *
   * @param tokenId - Unique token identifier
   *
   * @example
   * await redisService.deleteRefreshToken('token123');
   */
  async deleteRefreshToken(tokenId: string): Promise<void> {
    try {
      await this.client.del(tokenId);
      this.logger.debug(`Refresh token deleted: ${tokenId}`);
    } catch (error) {
      this.logger.error(`Failed to delete refresh token: ${tokenId}`, error);
    }
  }

  /**
   * Delete all refresh tokens for a user (used for logout from all devices)
   *
   * @param userId - User ID
   *
   * @example
   * await redisService.deleteAllUserRefreshTokens('user123');
   */
  async deleteAllUserRefreshTokens(userId: string): Promise<void> {
    try {
      const pattern = `refresh_token:${userId}:*`;
      const keys = await this.client.keys(pattern);
      if (keys.length > 0) {
        await this.client.del(...keys);
        this.logger.debug(
          `Deleted ${keys.length} refresh tokens for user: ${userId}`,
        );
      }
    } catch (error) {
      this.logger.error(
        `Failed to delete refresh tokens for user: ${userId}`,
        error,
      );
    }
  }

  /**
   * Get all active refresh tokens for a user (for session management)
   *
   * @param userId - User ID
   * @returns Array of refresh token data with token IDs
   *
   * @example
   * const sessions = await redisService.getUserRefreshTokens('user123');
   * sessions.forEach(session => {
   *   console.log(`Device: ${session.deviceInfo}, IP: ${session.ipAddress}`);
   * });
   */
  async getUserRefreshTokens(
    userId: string,
  ): Promise<(RefreshTokenData & { tokenId: string })[]> {
    try {
      const pattern = `refresh_token:${userId}:*`;
      const keys = await this.client.keys(pattern);
      const tokens: (RefreshTokenData & { tokenId: string })[] = [];

      for (const key of keys) {
        const data = await this.getRefreshToken(key);
        if (data) {
          // Extract tokenId from the key: refresh_token:userId:tokenId
          const tokenId = key.split(':')[2];
          tokens.push({ ...data, tokenId });
        }
      }

      return tokens;
    } catch (error) {
      this.logger.error(
        `Failed to get refresh tokens for user: ${userId}`,
        error,
      );
      return [];
    }
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Get OTP time-to-live from configuration
   *
   * @returns TTL in seconds
   */
  private getOtpTtl(): number {
    return this.configService.get('OTP_EXPIRES_IN', 300000) / 1000; // Convert to seconds
  }

  /**
   * Calculate progressive block duration based on excess attempts
   *
   * @param excessAttempts - Number of attempts over the limit
   * @returns Block duration in milliseconds
   */
  private getBlockDuration(excessAttempts: number): number {
    // Progressive blocking: 1min, 5min, 15min, 30min, 1hour, 2hours, 4hours, 8hours, 24hours
    const durations = [
      60000, 300000, 900000, 1800000, 3600000, 7200000, 14400000, 28800000,
      86400000,
    ];
    const index = Math.min(excessAttempts - 1, durations.length - 1);
    return durations[index];
  }

  // ============================================================================
  // KEY GENERATION
  // ============================================================================

  /**
   * Generate OTP Redis key
   *
   * @param userId - User ID
   * @param type - OTP type
   * @returns Redis key for OTP storage
   *
   * @example
   * const key = redisService.generateOtpKey('user123', OtpType.EMAIL_VERIFICATION);
   * // Returns: 'otp:user123:EMAIL_VERIFICATION'
   */
  generateOtpKey(userId: string, type: OtpType): string {
    return `otp:${userId}:${type}`;
  }

  /**
   * Generate rate limit Redis key
   *
   * @param identifier - IP address or user ID
   * @param action - Action being rate limited
   * @returns Redis key for rate limiting
   *
   * @example
   * const key = redisService.generateRateLimitKey('192.168.1.1', 'login');
   * // Returns: 'rate_limit:login:192.168.1.1'
   */
  generateRateLimitKey(identifier: string, action: string): string {
    return `rate_limit:${action}:${identifier}`;
  }

  /**
   * Generate session Redis key
   *
   * @param userId - User ID
   * @returns Redis key for session storage
   *
   * @example
   * const key = redisService.generateSessionKey('user123');
   * // Returns: 'session:user123'
   */
  generateSessionKey(userId: string): string {
    return `session:${userId}`;
  }

  /**
   * Generate failed login attempts Redis key
   *
   * @param identifier - IP address or user ID
   * @returns Redis key for failed login tracking
   *
   * @example
   * const key = redisService.generateFailedLoginKey('192.168.1.1');
   * // Returns: 'failed_login:192.168.1.1'
   */
  generateFailedLoginKey(identifier: string): string {
    return `failed_login:${identifier}`;
  }

  /**
   * Generate refresh token Redis key
   *
   * @param userId - User ID
   * @param tokenId - Token identifier
   * @returns Redis key for refresh token storage
   *
   * @example
   * const key = redisService.generateRefreshTokenKey('user123', 'token456');
   * // Returns: 'refresh_token:user123:token456'
   */
  generateRefreshTokenKey(userId: string, tokenId: string): string {
    return `refresh_token:${userId}:${tokenId}`;
  }

  // ============================================================================
  // HEALTH MONITORING
  // ============================================================================

  /**
   * Check Redis connection health
   *
   * @returns True if Redis is responding, false otherwise
   *
   * @example
   * const isHealthy = await redisService.ping();
   * if (!isHealthy) {
   *   // Handle Redis connection issues
   * }
   */
  async ping(): Promise<boolean> {
    try {
      const result = await this.client.ping();
      return result === 'PONG';
    } catch (error) {
      this.logger.error('Redis ping failed', error);
      return false;
    }
  }

  /**
   * Clean up Redis connection on application shutdown
   *
   * @example
   * process.on('SIGTERM', async () => {
   *   await redisService.cleanup();
   *   process.exit(0);
   * });
   */
  async cleanup(): Promise<void> {
    try {
      await this.client.quit();
      this.logger.log('Redis connection closed');
    } catch (error) {
      this.logger.error('Failed to close Redis connection', error);
    }
  }
}

/**
 * Sample Usage:
 *
 * 1. OTP Management:
 *    const otpKey = redisService.generateOtpKey(userId, OtpType.EMAIL_VERIFICATION);
 *    await redisService.setOtp(otpKey, otpData, 300); // 5 minutes
 *    const otp = await redisService.getOtp(otpKey);
 *
 * 2. Rate Limiting:
 *    const rateKey = redisService.generateRateLimitKey(ip, 'login');
 *    const rateData = await redisService.checkRateLimit(rateKey, 5, 900000);
 *    if (rateData.blocked) throw new Error('Rate limit exceeded');
 *
 * 3. Refresh Token Management:
 *    const tokenKey = redisService.generateRefreshTokenKey(userId, tokenId);
 *    await redisService.setRefreshToken(tokenKey, tokenData, 604800); // 7 days
 *    const sessions = await redisService.getUserRefreshTokens(userId);
 *
 * 4. Security Features:
 *    const failedKey = redisService.generateFailedLoginKey(ip);
 *    const attempts = await redisService.incrementFailedLoginAttempts(failedKey, 900);
 *    if (attempts >= 5) await lockAccount(userId);
 *
 * 5. Health Check:
 *    const isHealthy = await redisService.ping();
 *    if (!isHealthy) {
 *      // Implement fallback or alert
 *    }
 */
