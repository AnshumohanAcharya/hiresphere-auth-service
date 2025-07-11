import {
  BadRequestException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { OtpType, User } from '@prisma/client';
import { EmailService } from '../email/email.service';
import { PrismaService } from '../database/prisma.service';
import { RedisService } from '../redis/redis.service';
import { EncryptionService } from '../security/encryption.service';
import { SecurityService } from '../security/security.service';
import { UsersService } from '../users/users.service';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';

export interface JwtPayload {
  sub: string;
  email: string;
  jti: string;
}

export interface TokenResponse {
  accessToken: string;
  refreshToken: string;
}

export interface UserResponse {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  isEmailVerified: boolean;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly usersService: UsersService,
    private readonly emailService: EmailService,
    private readonly prisma: PrismaService,
    private readonly encryptionService: EncryptionService,
    private readonly securityService: SecurityService,
    private readonly redisService: RedisService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  async register(
    registerDto: RegisterDto,
    ipAddress?: string,
    userAgent?: string,
  ) {
    const { email, firstName, lastName } = registerDto;

    // Check if user already exists
    const existingUser = await this.usersService.findUserByEmail(email);
    if (existingUser) {
      throw new BadRequestException('User with this email already exists');
    }

    // Create user
    const user = await this.usersService.createUser(registerDto);

    // Generate email verification OTP
    const otp = await this.securityService.generateAndStoreOtp(
      user.id,
      OtpType.EMAIL_VERIFICATION,
    );

    // Send verification email
    await this.emailService.sendOtpEmail(
      email,
      firstName,
      otp,
      'EMAIL_VERIFICATION',
    );

    // Log registration event
    await this.securityService.logSecurityEvent(
      user.id,
      'USER_REGISTERED',
      { email, firstName, lastName },
      ipAddress,
      userAgent,
    );

    return {
      message:
        'Registration successful. Please check your email for verification code.',
      user: this.sanitizeUser(user as User),
    };
  }

  async login(loginDto: LoginDto, ipAddress?: string, userAgent?: string) {
    const { email, password } = loginDto;

    // Validate user credentials
    const user = await this.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if email is verified
    if (!user.isEmailVerified) {
      throw new BadRequestException(
        'Please verify your email before logging in',
      );
    }

    // Generate tokens
    const tokens = await this.generateTokens(user.id, user.email);

    // Store refresh token in Redis
    const deviceInfo = this.extractDeviceInfo(userAgent || '');
    await this.redisService.setRefreshToken(
      tokens.refreshToken,
      {
        userId: user.id,
        deviceInfo,
        ipAddress,
        userAgent,
        createdAt: Date.now(),
        expiresAt:
          Date.now() +
          this.parseDurationToSeconds(
            this.configService.get('JWT_REFRESH_EXPIRES_IN', '7d'),
          ) *
            1000,
      },
      this.parseDurationToSeconds(
        this.configService.get('JWT_REFRESH_EXPIRES_IN', '7d'),
      ),
    );

    // Log successful login
    await this.securityService.logSecurityEvent(
      user.id,
      'LOGIN_SUCCESS',
      { email, deviceInfo },
      ipAddress,
      userAgent,
    );

    return {
      message: 'Login successful',
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: this.sanitizeUser(user),
    };
  }

  private extractDeviceInfo(userAgent: string): string {
    if (userAgent.includes('Mobile')) return 'Mobile';
    if (userAgent.includes('Tablet')) return 'Tablet';
    return 'Desktop';
  }

  private parseDurationToSeconds(duration: string): number {
    const value = parseInt(duration.slice(0, -1));
    const unit = duration.slice(-1);

    switch (unit) {
      case 's':
        return value;
      case 'm':
        return value * 60;
      case 'h':
        return value * 60 * 60;
      case 'd':
        return value * 24 * 60 * 60;
      case 'w':
        return value * 7 * 24 * 60 * 60;
      case 'y':
        return value * 365 * 24 * 60 * 60;
      default:
        return 7 * 24 * 60 * 60;
    }
  }

  async verifyOtp(
    verifyOtpDto: VerifyOtpDto,
    ipAddress?: string,
    userAgent?: string,
  ) {
    const { code, type, email } = verifyOtpDto;

    // Find user by email for email verification, or use userId for password reset
    let userId: string;
    if (type === OtpType.EMAIL_VERIFICATION) {
      const user = await this.usersService.findByEmail(email);
      userId = user.id;
    } else if (type === OtpType.PASSWORD_RESET) {
      // For password reset, we need to find user by email
      const user = await this.usersService.findByEmail(email);
      userId = user.id;
    } else {
      throw new BadRequestException('Invalid OTP type');
    }

    const result = await this.securityService.verifyOtp(userId, code, type);
    if (!result.isValid) {
      throw new BadRequestException(result.message);
    }

    // Handle different OTP types
    switch (type) {
      case OtpType.EMAIL_VERIFICATION: {
        await this.usersService.verifyEmail(userId);
        const verifiedUser = await this.usersService.findById(userId);
        if (!verifiedUser) {
          throw new BadRequestException('User not found after verification');
        }
        await this.emailService.sendWelcomeEmail(
          verifiedUser.email,
          verifiedUser.firstName,
        );

        // Log email verification event
        await this.securityService.logSecurityEvent(
          userId,
          'EMAIL_VERIFIED',
          { email },
          ipAddress,
          userAgent,
        );

        return {
          message: 'Email verified successfully. Welcome to HireSphere!',
        };
      }

      case OtpType.PASSWORD_RESET:
        // Log OTP verification for password reset
        await this.securityService.logSecurityEvent(
          userId,
          'PASSWORD_RESET_OTP_VERIFIED',
          { email },
          ipAddress,
          userAgent,
        );

        return {
          message:
            'OTP verified successfully. You can now reset your password.',
        };

      default:
        return {
          message: 'OTP verified successfully.',
        };
    }
  }

  async resendOtp(
    email: string,
    type: OtpType,
    ipAddress?: string,
    userAgent?: string,
  ) {
    const user = await this.usersService.findByEmail(email);

    // Check if user can resend OTP and generate new one
    const result = await this.securityService.resendOtp(user.id, type);
    if (!result.success) {
      throw new BadRequestException(result.message);
    }

    // Generate and send new OTP
    const otp = await this.securityService.generateAndStoreOtp(user.id, type);
    await this.emailService.sendOtpEmail(user.email, user.firstName, otp, type);

    // Log resend OTP event
    await this.securityService.logSecurityEvent(
      user.id,
      'OTP_RESENT',
      { email, type },
      ipAddress,
      userAgent,
    );

    return {
      message: 'OTP sent successfully',
    };
  }

  async forgotPassword(
    forgotPasswordDto: ForgotPasswordDto,
    ipAddress?: string,
    userAgent?: string,
  ) {
    const { email } = forgotPasswordDto;

    try {
      const user = await this.usersService.findByEmail(email);

      // Generate password reset OTP
      const otp = await this.securityService.generateAndStoreOtp(
        user.id,
        OtpType.PASSWORD_RESET,
      );

      // Send password reset email
      await this.emailService.sendOtpEmail(
        email,
        user.firstName,
        otp,
        'PASSWORD_RESET',
      );

      // Log password reset request
      await this.securityService.logSecurityEvent(
        user.id,
        'PASSWORD_RESET_REQUESTED',
        { email },
        ipAddress,
        userAgent,
      );

      return {
        message: 'Password reset instructions sent to your email',
      };
    } catch {
      // Don't reveal if email exists or not
      return {
        message:
          'If an account with this email exists, password reset instructions have been sent.',
      };
    }
  }

  async resetPassword(
    resetPasswordDto: ResetPasswordDto,
    ipAddress?: string,
    userAgent?: string,
  ) {
    const { email, otp, newPassword } = resetPasswordDto;

    try {
      const user = await this.usersService.findByEmail(email);

      // Verify OTP
      const otpResult = await this.securityService.verifyOtp(
        user.id,
        otp,
        OtpType.PASSWORD_RESET,
      );
      if (!otpResult.isValid) {
        throw new BadRequestException(otpResult.message);
      }

      // Validate new password strength
      const passwordValidation =
        this.securityService.validatePasswordStrength(newPassword);
      if (!passwordValidation.isValid) {
        throw new BadRequestException({
          message: 'Password does not meet security requirements',
          errors: passwordValidation.errors,
        });
      }

      // Update password
      await this.usersService.updatePassword(user.id, newPassword);

      // Log password reset
      await this.securityService.logSecurityEvent(
        user.id,
        'PASSWORD_RESET_SUCCESS',
        { email },
        ipAddress,
        userAgent,
      );

      return {
        message: 'Password reset successfully',
      };
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      throw new BadRequestException('Password reset failed');
    }
  }

  async refreshToken(refreshToken: string) {
    try {
      // Verify refresh token
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
      });

      // Check if token exists in Redis
      const tokenData = (await this.redisService.getRefreshToken(
        refreshToken,
      )) as {
        userId: string;
        deviceInfo?: string;
        ipAddress?: string;
        userAgent?: string;
      } | null;
      if (!tokenData) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Check if token belongs to the same user
      if (tokenData.userId !== payload.sub) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Get user details
      const user = await this.usersService.findById(payload.sub);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Generate new tokens
      const tokens = await this.generateTokens(user.id, user.email);

      // Store new refresh token
      await this.redisService.setRefreshToken(
        tokens.refreshToken,
        {
          userId: user.id,
          deviceInfo: tokenData.deviceInfo,
          ipAddress: tokenData.ipAddress,
          userAgent: tokenData.userAgent,
          createdAt: Date.now(),
          expiresAt:
            Date.now() +
            this.parseDurationToSeconds(
              this.configService.get('JWT_REFRESH_EXPIRES_IN', '7d'),
            ) *
              1000,
        },
        this.parseDurationToSeconds(
          this.configService.get('JWT_REFRESH_EXPIRES_IN', '7d'),
        ),
      );

      // Delete old refresh token
      await this.redisService.deleteRefreshToken(refreshToken);

      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async logout(userId: string) {
    // Get all user sessions
    const sessions = await this.redisService.getUserRefreshTokens(userId);

    // Delete all refresh tokens for the user
    await this.redisService.deleteAllUserRefreshTokens(userId);

    // Log logout event
    await this.securityService.logSecurityEvent(userId, 'LOGOUT', {
      sessionsCount: sessions.length,
    });

    return {
      message: 'Logout successful',
    };
  }

  async getUserSessions(userId: string) {
    const sessions = await this.redisService.getUserRefreshTokens(userId);
    return sessions.map((session) => ({
      tokenId: session.tokenId,
      deviceInfo: session.deviceInfo,
      ipAddress: session.ipAddress,
      userAgent: session.userAgent,
      createdAt: new Date(session.createdAt),
      expiresAt: new Date(session.expiresAt),
    }));
  }

  async revokeSession(userId: string, tokenId: string) {
    // Check if session exists and belongs to user
    const sessions = await this.redisService.getUserRefreshTokens(userId);
    const session = sessions.find((s) => s.tokenId === tokenId);

    if (!session) {
      throw new BadRequestException('Session not found');
    }

    // Delete the specific refresh token
    await this.redisService.deleteRefreshToken(tokenId);

    // Log session revocation
    await this.securityService.logSecurityEvent(userId, 'SESSION_REVOKED', {
      tokenId,
      deviceInfo: session.deviceInfo,
    });

    return {
      message: 'Session revoked successfully',
    };
  }

  async validateUser(email: string, password: string): Promise<User | null> {
    try {
      // Get the raw user from database for password comparison
      const user = await this.prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        return null;
      }

      const isPasswordValid = await this.encryptionService.comparePassword(
        password,
        user.password,
      );

      if (!isPasswordValid) {
        return null;
      }

      return user;
    } catch (error) {
      this.logger.error('Error validating user:', error);
      return null;
    }
  }

  private async generateTokens(
    userId: string,
    email: string,
  ): Promise<TokenResponse> {
    const payload: JwtPayload = {
      sub: userId,
      email,
      jti: this.encryptionService.generateSecureToken(),
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.configService.get('JWT_SECRET'),
        expiresIn: this.configService.get('JWT_EXPIRES_IN', '15m'),
      }),
      this.jwtService.signAsync(payload, {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get('JWT_REFRESH_EXPIRES_IN', '7d'),
      }),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  private sanitizeUser(user: User): UserResponse {
    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      isEmailVerified: user.isEmailVerified,
      isActive: user.isActive,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }
}
