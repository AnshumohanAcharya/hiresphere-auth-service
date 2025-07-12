import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { OtpType } from '@prisma/client';
import { PrismaService } from '../database/prisma.service';
import { RedisService } from '../redis/redis.service';

@Injectable()
export class SecurityService {
  private readonly logger = new Logger(SecurityService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
    private readonly redisService: RedisService,
  ) {}

  async handleFailedLogin(
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) return;

    const maxFailedAttempts = this.configService.get<number>(
      'MAX_FAILED_LOGIN_ATTEMPTS',
      5,
    );
    const lockoutDuration = this.configService.get<number>(
      'LOGIN_LOCKOUT_DURATION',
      15 * 60 * 1000,
    ); // 15 minutes
    const rateLimitWindow = this.configService.get<number>(
      'LOGIN_RATE_LIMIT_WINDOW',
      15 * 60 * 1000,
    ); // 15 minutes

    // Use Redis for rate limiting
    const rateLimitKey = this.redisService.generateFailedLoginKey(userId);
    const failedAttempts = await this.redisService.incrementFailedLoginAttempts(
      rateLimitKey,
      rateLimitWindow / 1000,
    );

    let lockedUntil: Date | null = null;

    if (failedAttempts >= maxFailedAttempts) {
      lockedUntil = new Date(Date.now() + lockoutDuration);

      // Update database with lock status
      await this.prisma.user.update({
        where: { id: userId },
        data: {
          failedLoginAttempts: failedAttempts,
          lockedUntil,
        },
      });
    } else {
      // Update database with current failed attempts
      await this.prisma.user.update({
        where: { id: userId },
        data: {
          failedLoginAttempts: failedAttempts,
        },
      });
    }

    // Log the failed attempt
    await this.logSecurityEvent(userId, 'FAILED_LOGIN', {
      ipAddress,
      userAgent,
      failedAttempts,
      lockedUntil,
    });
  }

  async resetFailedLoginAttempts(userId: string): Promise<void> {
    // Clear Redis cache
    const rateLimitKey = this.redisService.generateFailedLoginKey(userId);
    await this.redisService.resetFailedLoginAttempts(rateLimitKey);

    // Update database
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        failedLoginAttempts: 0,
        lockedUntil: null,
        lastLoginAt: new Date(),
      },
    });
  }

  async isAccountLocked(userId: string): Promise<boolean> {
    // Check Redis first for faster response
    const rateLimitKey = this.redisService.generateFailedLoginKey(userId);
    const failedAttempts =
      await this.redisService.getFailedLoginAttempts(rateLimitKey);
    const maxFailedAttempts = this.configService.get<number>(
      'MAX_FAILED_LOGIN_ATTEMPTS',
      5,
    );

    if (failedAttempts >= maxFailedAttempts) {
      return true;
    }

    // Fallback to database check
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { lockedUntil: true },
    });

    if (!user || !user.lockedUntil) {
      return false;
    }

    // Check if lockout period has expired
    if (user.lockedUntil < new Date()) {
      await this.resetFailedLoginAttempts(userId);
      return false;
    }

    return true;
  }

  // OTP Management with Redis
  async generateAndStoreOtp(userId: string, type: OtpType): Promise<string> {
    const otp = this.generateOtp();
    const expiresIn = this.configService.get<number>('OTP_EXPIRES_IN', 300000); // 5 minutes

    const otpData = {
      code: otp,
      attempts: 0,
      expiresAt: Date.now() + expiresIn,
      type,
      userId,
    };

    const otpKey = this.redisService.generateOtpKey(userId, type);
    await this.redisService.setOtp(otpKey, otpData, expiresIn / 1000);

    this.logger.debug(`OTP generated for user ${userId}, type: ${type}`);
    return otp;
  }

  async verifyOtp(
    userId: string,
    otp: string,
    type: OtpType,
  ): Promise<{ isValid: boolean; message: string }> {
    const otpKey = this.redisService.generateOtpKey(userId, type);
    const otpData = await this.redisService.getOtp(otpKey);

    if (!otpData) {
      return { isValid: false, message: 'OTP not found or expired' };
    }

    // Check if OTP has expired
    if (Date.now() > otpData.expiresAt) {
      await this.redisService.deleteOtp(otpKey);
      return { isValid: false, message: 'OTP has expired' };
    }

    if (otpData.attempts >= 3) {
      await this.redisService.deleteOtp(otpKey);
      return { isValid: false, message: 'Maximum OTP attempts exceeded' };
    }

    // Increment attempts
    const newAttempts = await this.redisService.incrementOtpAttempts(otpKey);

    // Verify OTP
    if (otpData.code === otp) {
      // OTP is valid, delete it
      await this.redisService.deleteOtp(otpKey);
      return { isValid: true, message: 'OTP verified successfully' };
    }

    // OTP is invalid
    if (newAttempts >= 3) {
      await this.redisService.deleteOtp(otpKey);
      return { isValid: false, message: 'Maximum OTP attempts exceeded' };
    }

    return {
      isValid: false,
      message: `Invalid OTP. ${3 - newAttempts} attempts remaining`,
    };
  }

  async resendOtp(
    userId: string,
    type: OtpType,
  ): Promise<{ success: boolean; message: string }> {
    const otpKey = this.redisService.generateOtpKey(userId, type);
    const existingOtp = await this.redisService.getOtp(otpKey);

    if (existingOtp) {
      const resendCooldown = this.configService.get<number>(
        'OTP_RESEND_COOLDOWN',
        60000,
      ); // 1 minute
      const timeSinceCreation =
        Date.now() -
        (existingOtp.expiresAt -
          this.configService.get('OTP_EXPIRES_IN', 300000));

      if (timeSinceCreation < resendCooldown) {
        const remainingTime = Math.ceil(
          (resendCooldown - timeSinceCreation) / 1000,
        );
        return {
          success: false,
          message: `Please wait ${remainingTime} seconds before requesting a new OTP`,
        };
      }
    }

    // Generate new OTP
    await this.generateAndStoreOtp(userId, type);

    return {
      success: true,
      message: 'New OTP generated successfully',
    };
  }

  private generateOtp(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  async logSecurityEvent(
    userId: string | null,
    action: string,
    details: Record<string, unknown>,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        userId,
        action,
        ipAddress,
        userAgent,
        details: details as any,
      },
    });
  }

  validatePasswordStrength(password: string): {
    isValid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }

    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  sanitizeUserData(user: Record<string, unknown>): Record<string, unknown> {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...sanitizedUser } = user;
    return sanitizedUser;
  }
}

/**
 * Sample Usage:
 *
 * 1. OTP Management:
 *    const otp = await securityService.generateAndStoreOtp(userId, OtpType.EMAIL_VERIFICATION);
 *    const result = await securityService.verifyOtp(userId, code, OtpType.EMAIL_VERIFICATION);
 *    const resendResult = await securityService.resendOtp(userId, OtpType.EMAIL_VERIFICATION);
 *
 * 2. Account Security:
 *    await securityService.handleFailedLogin(userId, ipAddress, userAgent);
 *    const isLocked = await securityService.isAccountLocked(userId);
 *    await securityService.resetFailedLoginAttempts(userId);
 *
 * 3. Password Validation:
 *    const validation = securityService.validatePasswordStrength(password);
 *    if (!validation.isValid) {
 *      console.log('Password errors:', validation.errors);
 *    }
 *
 * 4. Security Logging:
 *    await securityService.logSecurityEvent(userId, 'LOGIN_ATTEMPT', { success: true }, ip, userAgent);
 *
 * 5. Data Sanitization:
 *    const cleanUser = securityService.sanitizeUserData(userData);
 */
