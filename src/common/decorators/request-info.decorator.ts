import { Request } from 'express';

import { createParamDecorator, ExecutionContext } from '@nestjs/common';

// Define proper interfaces for request info
interface RequestInfo {
  ip: string;
  userAgent: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  userId?: string;
}

interface RequestWithUser extends Request {
  user?: {
    id: string;
    email: string;
    isActive: boolean;
  };
}

/**
 * Custom decorator to automatically extract comprehensive request information
 *
 * @example
 * ```typescript
 * @Post('register')
 * async register(
 *   @Body() registerDto: RegisterDto,
 *   @RequestInfo() requestInfo: RequestInfo
 * ) {
 *   console.log('IP:', requestInfo.ip);
 *   console.log('User Agent:', requestInfo.userAgent);
 *   console.log('Referer:', requestInfo.referer);
 * }
 * ```
 */
export const RequestInfo = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): RequestInfo => {
    const request = ctx.switchToHttp().getRequest<RequestWithUser>();

    // Get IP address with proper typing
    const ip =
      request.socket?.remoteAddress ||
      (request.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      'unknown';

    // Get user agent with proper typing
    const userAgent = (request.headers['user-agent'] as string) || 'unknown';

    // Get forwarded method and URL with proper typing
    const method =
      (request.headers['x-forwarded-method'] as string) || request.method;
    const url = (request.headers['x-forwarded-url'] as string) || request.url;

    // Extract headers safely
    const headers: Record<string, string> = {};
    Object.keys(request.headers).forEach((key) => {
      const value = request.headers[key];
      if (typeof value === 'string') {
        headers[key] = value;
      } else if (Array.isArray(value)) {
        headers[key] = value[0] || '';
      }
    });

    // Get user ID if available
    const userId = request.user?.id;

    return {
      ip,
      userAgent,
      method,
      url,
      headers,
      userId,
    };
  },
);
