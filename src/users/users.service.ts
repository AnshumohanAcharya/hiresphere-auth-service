import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { User } from '@prisma/client';
import { RegisterDto } from '../auth/dto/register.dto';
import { PrismaService } from '../database/prisma.service';
import { EncryptionService } from '../security/encryption.service';
import { SecurityService } from '../security/security.service';

// Define proper interfaces for user data
export interface UserResponse {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  isEmailVerified: boolean;
  isActive: boolean;
  lastLoginAt: Date | null;
  failedLoginAttempts: number;
  lockedUntil: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface UserProfile {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  isEmailVerified: boolean;
  isActive: boolean;
  lastLoginAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

@Injectable()
export class UsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly encryptionService: EncryptionService,
    private readonly securityService: SecurityService,
  ) {}

  async createUser(registerDto: RegisterDto): Promise<UserResponse> {
    const { email, password, firstName, lastName } = registerDto;

    // Check if user already exists
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    // Hash password
    const hashedPassword = await this.encryptionService.hashPassword(password);

    // Create user
    const user = await this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        firstName,
        lastName,
      },
    });

    // Return sanitized user data
    return this.securityService.sanitizeUserData(
      user,
    ) as unknown as UserResponse;
  }

  async findByEmail(email: string): Promise<UserResponse> {
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.securityService.sanitizeUserData(
      user,
    ) as unknown as UserResponse;
  }

  async findUserByEmail(email: string): Promise<UserResponse | null> {
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return null;
    }

    return this.securityService.sanitizeUserData(
      user,
    ) as unknown as UserResponse;
  }

  async findById(id: string): Promise<UserResponse | null> {
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      return null;
    }

    return this.securityService.sanitizeUserData(
      user,
    ) as unknown as UserResponse;
  }

  async updateUser(
    id: string,
    updateData: Partial<User>,
  ): Promise<UserResponse> {
    const user = await this.prisma.user.update({
      where: { id },
      data: updateData,
    });

    return this.securityService.sanitizeUserData(
      user,
    ) as unknown as UserResponse;
  }

  async verifyEmail(id: string): Promise<UserResponse> {
    const user = await this.prisma.user.update({
      where: { id },
      data: { isEmailVerified: true },
    });

    return this.securityService.sanitizeUserData(
      user,
    ) as unknown as UserResponse;
  }

  async updatePassword(id: string, newPassword: string): Promise<void> {
    // Hash new password
    const hashedPassword =
      await this.encryptionService.hashPassword(newPassword);

    // Update password and reset failed login attempts
    await this.prisma.user.update({
      where: { id },
      data: {
        password: hashedPassword,
        failedLoginAttempts: 0,
        lockedUntil: null,
      },
    });
  }

  async deleteUser(id: string): Promise<void> {
    await this.prisma.user.delete({
      where: { id },
    });
  }

  async getProfile(id: string): Promise<UserProfile> {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        isEmailVerified: true,
        isActive: true,
        lastLoginAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async findAll(options?: {
    limit?: number;
    offset?: number;
    search?: string;
  }): Promise<UserResponse[]> {
    const { limit = 20, offset = 0, search } = options || {};

    const where = search
      ? {
          OR: [
            { email: { contains: search, mode: 'insensitive' as const } },
            { firstName: { contains: search, mode: 'insensitive' as const } },
            { lastName: { contains: search, mode: 'insensitive' as const } },
          ],
        }
      : {};

    const users = await this.prisma.user.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: limit,
      skip: offset,
    });

    return users.map(
      (user) =>
        this.securityService.sanitizeUserData(user) as unknown as UserResponse,
    );
  }
}
