import { Resolver, Mutation, Args, Context } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { AuthService } from '../../auth/auth.service';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import {
  AuthResponse,
  RegisterResponse,
  VerifyOtpResponse,
  ForgotPasswordResponse,
  ResetPasswordResponse,
  RefreshTokenResponse,
} from '../types/auth.type';
import {
  RegisterInput,
  LoginInput,
  VerifyOtpInput,
  ForgotPasswordInput,
  ResetPasswordInput,
  RefreshTokenInput,
  ResendOtpInput,
} from '../inputs/auth.input';
import { DeviceInfo } from '../../common/decorators/device-info.decorator';
import {
  AuthResponseDto,
  RegisterResponseDto,
  VerifyOtpResponseDto,
  ForgotPasswordResponseDto,
  ResetPasswordResponseDto,
} from '../../common/dto/response.dto';
import {
  createGraphQLError,
  USER_NOT_FOUND,
} from '../../common/utils/graphql-errors';

@Resolver()
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}

  @Mutation(() => RegisterResponse)
  async register(
    @Args('input') input: RegisterInput,
    @DeviceInfo() deviceInfo: { ipAddress: string; userAgent: string },
  ): Promise<RegisterResponse> {
    try {
      const result = await this.authService.register(
        {
          email: input.email,
          firstName: input.firstName,
          lastName: input.lastName,
          password: input.password,
        },
        deviceInfo.ipAddress,
        deviceInfo.userAgent,
      );

      return RegisterResponseDto.success(result.message, result.user.id);
    } catch (error) {
      if (error instanceof Error && error.message.includes('already exists')) {
        throw createGraphQLError(
          'User with this email already exists',
          'USER_ALREADY_EXISTS',
          409,
        );
      }
      throw error;
    }
  }

  @Mutation(() => AuthResponse)
  async login(
    @Args('input') input: LoginInput,
    @DeviceInfo() deviceInfo: { ipAddress: string; userAgent: string },
  ): Promise<AuthResponse> {
    try {
      const result = await this.authService.login(
        {
          email: input.email,
          password: input.password,
        },
        deviceInfo.ipAddress,
        deviceInfo.userAgent,
      );

      return AuthResponseDto.fromAuthResult(result, result.user);
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.includes('Invalid credentials')
      ) {
        throw createGraphQLError(
          'Invalid credentials',
          'INVALID_CREDENTIALS',
          401,
        );
      }
      if (
        error instanceof Error &&
        error.message.includes('verify your email')
      ) {
        throw createGraphQLError(
          'Please verify your email before logging in',
          'EMAIL_NOT_VERIFIED',
          403,
        );
      }
      throw error;
    }
  }

  @Mutation(() => VerifyOtpResponse)
  async verifyOtp(
    @Args('input') input: VerifyOtpInput,
    @DeviceInfo() deviceInfo: { ipAddress: string; userAgent: string },
  ): Promise<VerifyOtpResponse> {
    try {
      const result = await this.authService.verifyOtp(
        {
          email: input.email,
          code: input.otp,
          type: input.type,
        },
        deviceInfo.ipAddress,
        deviceInfo.userAgent,
      );

      return VerifyOtpResponseDto.success(result.message);
    } catch (error) {
      if (error instanceof Error && error.message.includes('Invalid OTP')) {
        throw createGraphQLError('Invalid OTP', 'OTP_INVALID', 400);
      }
      if (error instanceof Error && error.message.includes('expired')) {
        throw createGraphQLError('OTP has expired', 'OTP_EXPIRED', 410);
      }
      if (
        error instanceof Error &&
        error.message.includes('Maximum OTP attempts')
      ) {
        throw createGraphQLError(
          'Maximum OTP attempts exceeded',
          'TOO_MANY_ATTEMPTS',
          429,
        );
      }
      throw error;
    }
  }

  @Mutation(() => ForgotPasswordResponse)
  async forgotPassword(
    @Args('input') input: ForgotPasswordInput,
    @DeviceInfo() deviceInfo: { ipAddress: string; userAgent: string },
  ): Promise<ForgotPasswordResponse> {
    try {
      const result = await this.authService.forgotPassword(
        {
          email: input.email,
        },
        deviceInfo.ipAddress,
        deviceInfo.userAgent,
      );

      return ForgotPasswordResponseDto.success(result.message);
    } catch (error) {
      if (error instanceof Error && error.message.includes('User not found')) {
        throw createGraphQLError('User not found', USER_NOT_FOUND, 404);
      }
      throw error;
    }
  }

  @Mutation(() => ResetPasswordResponse)
  async resetPassword(
    @Args('input') input: ResetPasswordInput,
    @DeviceInfo() deviceInfo: { ipAddress: string; userAgent: string },
  ): Promise<ResetPasswordResponse> {
    try {
      const result = await this.authService.resetPassword(
        {
          email: input.email,
          otp: input.otp,
          newPassword: input.newPassword,
        },
        deviceInfo.ipAddress,
        deviceInfo.userAgent,
      );

      return ResetPasswordResponseDto.success(result.message);
    } catch (error) {
      if (error instanceof Error && error.message.includes('Invalid OTP')) {
        throw createGraphQLError('Invalid OTP', 'OTP_INVALID', 400);
      }
      if (error instanceof Error && error.message.includes('expired')) {
        throw createGraphQLError('OTP has expired', 'OTP_EXPIRED', 410);
      }
      throw error;
    }
  }

  @Mutation(() => RefreshTokenResponse)
  async refreshToken(
    @Args('input') input: RefreshTokenInput,
  ): Promise<RefreshTokenResponse> {
    try {
      const result = await this.authService.refreshToken(input.refreshToken);

      return {
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        message: 'Token refreshed successfully',
      };
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.includes('Invalid refresh token')
      ) {
        throw createGraphQLError(
          'Invalid refresh token',
          'INVALID_REFRESH_TOKEN',
          401,
        );
      }
      throw error;
    }
  }

  @Mutation(() => ForgotPasswordResponse)
  async resendOtp(
    @Args('input') input: ResendOtpInput,
    @DeviceInfo() deviceInfo: { ipAddress: string; userAgent: string },
  ): Promise<ForgotPasswordResponse> {
    try {
      const result = await this.authService.resendOtp(
        input.email,
        input.type,
        deviceInfo.ipAddress,
        deviceInfo.userAgent,
      );

      return ForgotPasswordResponseDto.success(result.message);
    } catch (error) {
      if (error instanceof Error && error.message.includes('User not found')) {
        throw createGraphQLError('User not found', USER_NOT_FOUND, 404);
      }
      if (error instanceof Error && error.message.includes('Please wait')) {
        throw createGraphQLError(error.message, 'RESEND_COOLDOWN', 429);
      }
      throw error;
    }
  }

  @Mutation(() => String)
  @UseGuards(JwtAuthGuard)
  async logout(@Context() context: any): Promise<string> {
    const { req } = context;
    const userId = req.user.sub;

    await this.authService.logout(userId);

    return 'Logged out successfully';
  }
}
