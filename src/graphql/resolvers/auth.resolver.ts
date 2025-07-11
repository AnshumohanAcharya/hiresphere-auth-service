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
import { OtpType } from '@prisma/client';

@Resolver()
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}

  @Mutation(() => RegisterResponse)
  async register(
    @Args('input') input: RegisterInput,
    @Context() context: any,
  ): Promise<RegisterResponse> {
    const { req } = context;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];

    const result = await this.authService.register(
      {
        email: input.email,
        firstName: input.firstName,
        lastName: input.lastName,
        password: input.password,
      },
      ipAddress,
      userAgent,
    );

    return {
      message: result.message,
      userId: result.user.id,
      emailSent: true,
    };
  }

  @Mutation(() => AuthResponse)
  async login(
    @Args('input') input: LoginInput,
    @Context() context: any,
  ): Promise<AuthResponse> {
    const { req } = context;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];

    const result = await this.authService.login(
      {
        email: input.email,
        password: input.password,
      },
      ipAddress,
      userAgent,
    );

    return {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      user: {
        id: result.user.id,
        email: result.user.email,
        firstName: result.user.firstName,
        lastName: result.user.lastName,
        isEmailVerified: result.user.isEmailVerified,
        isActive: result.user.isActive,
        createdAt: result.user.createdAt,
        updatedAt: result.user.updatedAt,
      },
      message: result.message,
    };
  }

  @Mutation(() => VerifyOtpResponse)
  async verifyOtp(
    @Args('input') input: VerifyOtpInput,
    @Context() context: any,
  ): Promise<VerifyOtpResponse> {
    const { req } = context;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];

    const otpType = OtpType.EMAIL_VERIFICATION;

    const result = await this.authService.verifyOtp(
      {
        email: input.email,
        code: input.otp,
        type: otpType,
      },
      ipAddress,
      userAgent,
    );

    return {
      message: result.message,
      isVerified: true,
    };
  }

  @Mutation(() => ForgotPasswordResponse)
  async forgotPassword(
    @Args('input') input: ForgotPasswordInput,
    @Context() context: any,
  ): Promise<ForgotPasswordResponse> {
    const { req } = context;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];

    const result = await this.authService.forgotPassword(
      {
        email: input.email,
      },
      ipAddress,
      userAgent,
    );

    return {
      message: result.message,
      emailSent: true,
    };
  }

  @Mutation(() => ResetPasswordResponse)
  async resetPassword(
    @Args('input') input: ResetPasswordInput,
    @Context() context: any,
  ): Promise<ResetPasswordResponse> {
    const { req } = context;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];

    const result = await this.authService.resetPassword(
      {
        email: input.email,
        otp: input.otp,
        newPassword: input.newPassword,
      },
      ipAddress,
      userAgent,
    );

    return {
      message: result.message,
      success: true,
    };
  }

  @Mutation(() => RefreshTokenResponse)
  async refreshToken(
    @Args('input') input: RefreshTokenInput,
  ): Promise<RefreshTokenResponse> {
    const result = await this.authService.refreshToken(input.refreshToken);

    return {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      message: 'Token refreshed successfully',
    };
  }

  @Mutation(() => ForgotPasswordResponse)
  async resendOtp(
    @Args('input') input: ResendOtpInput,
    @Context() context: any,
  ): Promise<ForgotPasswordResponse> {
    const { req } = context;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];

    const otpType = OtpType.EMAIL_VERIFICATION;

    const result = await this.authService.resendOtp(
      input.email,
      otpType,
      ipAddress,
      userAgent,
    );

    return {
      message: result.message,
      emailSent: true,
    };
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
