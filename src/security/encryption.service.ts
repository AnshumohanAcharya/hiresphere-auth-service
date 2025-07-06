import * as bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';

import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class EncryptionService {
  constructor(
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  async hashPassword(password: string): Promise<string> {
    try {
      const saltRounds = parseInt(
        this.configService.get('BCRYPT_ROUNDS', '12'),
        10,
      );

      // Validate salt rounds
      if (isNaN(saltRounds) || saltRounds < 10 || saltRounds > 14) {
        throw new Error(
          'Invalid BCRYPT_ROUNDS configuration. Must be between 10 and 14.',
        );
      }

      return bcrypt.hash(password, saltRounds);
    } catch (error: unknown) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Password hashing failed: ${errorMessage}`);
    }
  }

  async comparePassword(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }

  generateAccessToken(payload: Record<string, unknown>): string {
    return this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_SECRET'),
      expiresIn: this.configService.get('JWT_EXPIRES_IN', '15m'),
    });
  }

  generateRefreshToken(payload: Record<string, unknown>): string {
    return this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get('JWT_REFRESH_EXPIRES_IN', '7d'),
    });
  }

  verifyToken(token: string, isRefreshToken = false): Record<string, unknown> {
    try {
      const secret = isRefreshToken
        ? this.configService.get('JWT_REFRESH_SECRET')
        : this.configService.get('JWT_SECRET');

      return this.jwtService.verify(token, { secret });
    } catch {
      throw new Error('Invalid token');
    }
  }

  verifyRefreshToken(token: string): Record<string, unknown> {
    try {
      return this.jwtService.verify(token, {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
      });
    } catch {
      throw new Error('Invalid refresh token');
    }
  }

  generateSecureToken(): string {
    return uuidv4();
  }
}
