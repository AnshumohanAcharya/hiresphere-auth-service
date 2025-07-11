import { User } from '@prisma/client';

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

export class AuthResponseDto {
  static fromAuthResult(result: any, user: UserResponse) {
    return {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isEmailVerified: user.isEmailVerified,
        isActive: user.isActive,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      },
      message: result.message,
    };
  }
}

export class UserResponseDto {
  static fromUser(user: User) {
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

  static fromUsers(users: User[]) {
    return users.map((user) => UserResponseDto.fromUser(user));
  }
}

export class RegisterResponseDto {
  static success(message: string, userId: string) {
    return {
      message,
      userId,
      emailSent: true,
    };
  }
}

export class VerifyOtpResponseDto {
  static success(message: string) {
    return {
      message,
      isVerified: true,
    };
  }
}

export class ForgotPasswordResponseDto {
  static success(message: string) {
    return {
      message,
      emailSent: true,
    };
  }
}

export class ResetPasswordResponseDto {
  static success(message: string) {
    return {
      message,
      success: true,
    };
  }
}
