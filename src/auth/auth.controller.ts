import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Request,
  UseGuards,
  Res,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';

import { RateLimit } from '../common/decorators/rate-limit.decorator';
import { RequestInfo } from '../common/decorators/request-info.decorator';
import { RequestInfoDto } from '../common/dto/request-info.dto';
import { RedisRateLimitGuard } from '../common/guards/redis-rate-limit.guard';
import { UsersService } from '../users/users.service';
import { AuthService } from './auth.service';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { ResendOtpDto } from './dto/resend-otp.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { Response } from 'express';
import { CookieService } from '../utils/cookie.service';

// Define proper interfaces for request objects
interface AuthenticatedRequest extends Request {
  user: {
    id: string;
    email: string;
    isActive: boolean;
  };
}

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
    private readonly cookieService: CookieService,
  ) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @UseGuards(RedisRateLimitGuard)
  @RateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 5 }) // 5 attempts per 15 minutes
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({
    status: 201,
    description: 'User registered successfully. OTP sent to email.',
  })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 409, description: 'User already exists' })
  async register(
    @Body() registerDto: RegisterDto,
    @RequestInfo() requestInfo: RequestInfoDto,
  ) {
    return this.authService.register(
      registerDto,
      requestInfo.ip,
      requestInfo.userAgent,
    );
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @UseGuards(RedisRateLimitGuard)
  @RateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 5 }) // 5 attempts per 15 minutes
  @ApiOperation({ summary: 'Login user' })
  @ApiResponse({
    status: 200,
    description: 'Login successful. Returns access and refresh tokens.',
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiResponse({ status: 423, description: 'Account locked' })
  async login(
    @Body() loginDto: LoginDto,
    @RequestInfo() requestInfo: RequestInfoDto,
    @Res() res: Response,
  ) {
    const result = await this.authService.login(
      loginDto,
      requestInfo.ip,
      requestInfo.userAgent,
    );

    // Set cookies
    this.cookieService.setResponse(res);
    this.cookieService.setCookie('accessToken', result.accessToken, {
      httpOnly: false, // Set to false for testing
      secure: false, // Set to false for development
      maxAge: 15 * 60, // 15 minutes
    });

    this.cookieService.setCookie('refreshToken', result.refreshToken, {
      httpOnly: false, // Set to false for testing
      secure: false, // Set to false for development
      maxAge: 7 * 24 * 60 * 60, // 7 days
    });
    return res.json(result);
  }

  @Post('verify-otp')
  @HttpCode(HttpStatus.OK)
  @UseGuards(RedisRateLimitGuard)
  @RateLimit({ windowMs: 5 * 60 * 1000, maxRequests: 10 }) // 10 attempts per 5 minutes
  @ApiOperation({ summary: 'Verify OTP code' })
  @ApiResponse({
    status: 200,
    description: 'OTP verified successfully',
  })
  @ApiResponse({ status: 400, description: 'Invalid OTP' })
  @ApiResponse({ status: 410, description: 'OTP expired' })
  async verifyOtp(
    @Body() verifyOtpDto: VerifyOtpDto,
    @RequestInfo() requestInfo: RequestInfoDto,
  ) {
    return this.authService.verifyOtp(
      verifyOtpDto,
      requestInfo.ip,
      requestInfo.userAgent,
    );
  }

  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  @UseGuards(RedisRateLimitGuard)
  @RateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 3 }) // 3 attempts per 15 minutes
  @ApiOperation({ summary: 'Request password reset' })
  @ApiResponse({
    status: 200,
    description: 'Password reset OTP sent to email',
  })
  @ApiResponse({ status: 404, description: 'User not found' })
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
    @RequestInfo() requestInfo: RequestInfoDto,
  ) {
    return this.authService.forgotPassword(
      forgotPasswordDto,
      requestInfo.ip,
      requestInfo.userAgent,
    );
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @UseGuards(RedisRateLimitGuard)
  @RateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 5 }) // 5 attempts per 15 minutes
  @ApiOperation({ summary: 'Reset password with OTP' })
  @ApiResponse({
    status: 200,
    description: 'Password reset successfully',
  })
  @ApiResponse({ status: 400, description: 'Invalid OTP or password' })
  @ApiResponse({ status: 410, description: 'OTP expired' })
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
    @RequestInfo() requestInfo: RequestInfoDto,
  ) {
    return this.authService.resetPassword(
      resetPasswordDto,
      requestInfo.ip,
      requestInfo.userAgent,
    );
  }

  @Post('resend-otp')
  @HttpCode(HttpStatus.OK)
  @UseGuards(RedisRateLimitGuard)
  @RateLimit({ windowMs: 5 * 60 * 1000, maxRequests: 3 }) // 3 attempts per 5 minutes
  @ApiOperation({ summary: 'Resend OTP code' })
  @ApiResponse({
    status: 200,
    description: 'OTP resent successfully',
  })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiResponse({ status: 429, description: 'Too many resend attempts' })
  async resendOtp(
    @Body() resendOtpDto: ResendOtpDto,
    @RequestInfo() requestInfo: RequestInfoDto,
  ) {
    return this.authService.resendOtp(
      resendOtpDto.email,
      resendOtpDto.type,
      requestInfo.ip,
      requestInfo.userAgent,
    );
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @UseGuards(RedisRateLimitGuard)
  @RateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 10 }) // 10 attempts per 15 minutes
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiResponse({
    status: 200,
    description: 'New access token generated',
  })
  @ApiResponse({ status: 401, description: 'Invalid refresh token' })
  async refreshToken(
    @Body() refreshTokenDto: RefreshTokenDto,
    @Res() res: Response,
  ) {
    const result = await this.authService.refreshToken(
      refreshTokenDto.refreshToken,
    );

    // Set new cookies
    this.cookieService.setResponse(res);
    this.cookieService.setCookie('accessToken', result.accessToken, {
      httpOnly: false, // Set to false for testing
      secure: false, // Set to false for development
      maxAge: 15 * 60, // 15 minutes
    });

    this.cookieService.setCookie('refreshToken', result.refreshToken, {
      httpOnly: false, // Set to false for testing
      secure: false, // Set to false for development
      maxAge: 7 * 24 * 60 * 60, // 7 days
    });

    return res.json(result);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Logout user' })
  @ApiResponse({
    status: 200,
    description: 'Logout successful',
  })
  async logout(@Request() req: AuthenticatedRequest, @Res() res: Response) {
    this.cookieService.setResponse(res);
    this.cookieService.clearCookie('access_token');
    this.cookieService.clearCookie('refresh_token');
    const result = await this.authService.logout(req.user.id);
    return res.json(result);
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get user profile' })
  @ApiResponse({
    status: 200,
    description: 'User profile retrieved successfully',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getProfile(@Request() req: AuthenticatedRequest) {
    const user = await this.usersService.findById(req.user.id);
    if (!user) {
      throw new Error('User not found');
    }
    return user;
  }

  @Get('sessions')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get user sessions' })
  @ApiResponse({
    status: 200,
    description: 'User sessions retrieved successfully',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getSessions(@Request() req: AuthenticatedRequest) {
    return this.authService.getUserSessions(req.user.id);
  }

  @Post('sessions/:tokenId/revoke')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Revoke a specific session' })
  @ApiResponse({
    status: 200,
    description: 'Session revoked successfully',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Session not found' })
  async revokeSession(
    @Request() req: AuthenticatedRequest,
    @Param('tokenId') tokenId: string,
  ) {
    return this.authService.revokeSession(req.user.id, tokenId);
  }
}
