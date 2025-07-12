import { Request, Response } from 'express';
import { Observable } from 'rxjs';
import { catchError, tap } from 'rxjs/operators';
import { GqlExecutionContext } from '@nestjs/graphql';
import { SecurityService } from '../../security/security.service';

import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';

// Define proper interfaces
interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
  };
}

interface RequestHeaders {
  [key: string]: string | string[] | undefined;
}

interface AuditLogData {
  timestamp: Date;
  method: string;
  url: string;
  ip: string;
  userAgent: string;
  userId?: string;
  requestHeaders: Record<string, string>;
  requestBody?: unknown;
  responseStatus: number;
  responseTime: number;
  error?: string;
}

interface RequestInfo {
  method: string;
  url: string;
  userId?: string;
  ip: string;
  userAgent: string;
  headers: Record<string, string>;
  body?: unknown;
}

@Injectable()
export class AuditLogInterceptor implements NestInterceptor {
  private readonly logger = new Logger(AuditLogInterceptor.name);

  constructor(private readonly securityService: SecurityService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = this.getRequest(context);
    const response = this.getResponse(context);
    const startTime = Date.now();

    // Add null check for request
    if (!request) {
      this.logger.warn('Request object is undefined in AuditLogInterceptor');
      return next.handle();
    }

    // Extract request information with proper typing and null checks
    const ip = this.getClientIp(request);
    const userAgent = this.getUserAgent(request?.headers || {});
    const method = request?.method || 'UNKNOWN';
    const url = request?.url || 'unknown';
    const userId = request?.user?.id;
    const requestHeaders = this.sanitizeHeaders(request?.headers || {});
    const requestBody = this.sanitizeRequestBody(request?.body);

    // Log successful requests
    const successHandler = tap(() => {
      const responseTime = Date.now() - startTime;
      const auditData: AuditLogData = {
        timestamp: new Date(),
        method,
        url,
        ip,
        userAgent,
        userId,
        requestHeaders,
        requestBody,
        responseStatus: response?.statusCode || 200,
        responseTime,
      };

      this.logAuditEvent(auditData);
    });

    // Log errors
    const errorHandler = catchError((error: unknown) => {
      const responseTime = Date.now() - startTime;
      const errorObj = error as { status?: number; message?: string };
      const auditData: AuditLogData = {
        timestamp: new Date(),
        method,
        url,
        ip,
        userAgent,
        userId,
        requestHeaders,
        requestBody,
        responseStatus: errorObj.status || 500,
        responseTime,
        error: errorObj.message || 'Unknown error',
      };

      this.logAuditEvent(auditData);
      throw error;
    });

    return next.handle().pipe(successHandler, errorHandler);
  }

  private getRequest(context: ExecutionContext): AuthenticatedRequest | null {
    // Handle GraphQL context
    if (context.getType<string>() === 'graphql') {
      const gqlContext = GqlExecutionContext.create(context);
      return gqlContext.getContext().req as AuthenticatedRequest | null;
    }

    // Handle HTTP context
    return context.switchToHttp().getRequest<AuthenticatedRequest>();
  }

  private getResponse(context: ExecutionContext): Response | null {
    // Handle GraphQL context
    if (context.getType<string>() === 'graphql') {
      const gqlContext = GqlExecutionContext.create(context);
      const res = gqlContext.getContext().res as Response | null;
      return res;
    }

    // Handle HTTP context
    const res = context.switchToHttp().getResponse<Response>();
    return res;
  }

  private getClientIp(request: AuthenticatedRequest): string {
    try {
      // Check if request exists and has ip property
      if (request && request.ip) {
        return request.ip;
      }

      // Check if socket exists and has remoteAddress
      if (request?.socket?.remoteAddress) {
        return request.socket.remoteAddress;
      }

      // Check for x-forwarded-for header
      const forwardedFor = request?.headers?.['x-forwarded-for'];
      if (forwardedFor && typeof forwardedFor === 'string') {
        return forwardedFor.split(',')[0].trim();
      }

      // Check for x-real-ip header (common with nginx)
      const realIp = request?.headers?.['x-real-ip'];
      if (realIp && typeof realIp === 'string') {
        return realIp;
      }

      // Check for cf-connecting-ip header (Cloudflare)
      const cfIp = request?.headers?.['cf-connecting-ip'];
      if (cfIp && typeof cfIp === 'string') {
        return cfIp;
      }

      // Fallback to localhost for development
      return '127.0.0.1';
    } catch (error) {
      this.logger.warn('Error getting client IP, using fallback', error);
      return '127.0.0.1';
    }
  }

  private getUserAgent(headers: RequestHeaders): string {
    const userAgent = headers['user-agent'];
    if (typeof userAgent === 'string') {
      return userAgent;
    }
    if (Array.isArray(userAgent)) {
      return userAgent[0] || 'unknown';
    }
    return 'unknown';
  }

  private sanitizeHeaders(headers: RequestHeaders): Record<string, string> {
    const sanitized: Record<string, string> = {};
    const sensitiveHeaders = ['authorization', 'cookie', 'x-api-key'];

    Object.entries(headers).forEach(([key, value]) => {
      if (sensitiveHeaders.includes(key.toLowerCase())) {
        sanitized[key] = '[REDACTED]';
      } else {
        if (Array.isArray(value)) {
          sanitized[key] = value[0] || '';
        } else if (typeof value === 'string') {
          sanitized[key] = value;
        } else {
          sanitized[key] = '';
        }
      }
    });

    return sanitized;
  }

  private sanitizeRequestBody(body: unknown): unknown {
    if (!body || typeof body !== 'object') return undefined;

    const sensitiveFields = [
      'password',
      'confirmPassword',
      'currentPassword',
      'refreshToken',
      'token',
    ];
    const sanitized = { ...(body as Record<string, unknown>) };

    sensitiveFields.forEach((field) => {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    });

    return sanitized;
  }

  private logAuditEvent(auditData: AuditLogData): void {
    const logMessage = `AUDIT: ${auditData.method} ${auditData.url} - ${auditData.responseStatus} (${auditData.responseTime}ms) - IP: ${auditData.ip} - User: ${auditData.userId || 'anonymous'}`;

    if (auditData.error) {
      this.logger.error(logMessage, auditData.error);
    } else {
      this.logger.log(logMessage);
    }

    // In a production environment, you might want to store this in a database
    // or send it to a logging service like ELK stack, Splunk, etc.
  }

  private async logRequest(
    requestInfo: RequestInfo,
    statusCode: number,
    responseTime: number,
    responseData?: unknown,
    errorMessage?: string,
  ) {
    try {
      const action = this.determineAction(requestInfo.method, requestInfo.url);

      await this.securityService.logSecurityEvent(
        requestInfo.userId || null,
        action,
        {
          method: requestInfo.method,
          url: requestInfo.url,
          statusCode,
          responseTime,
          ip: requestInfo.ip,
          userAgent: requestInfo.userAgent,
          referer:
            requestInfo.headers.referer || requestInfo.headers.referrer || '',
          origin: requestInfo.headers.origin || '',
          host: requestInfo.headers.host || '',
          error: errorMessage,
          // Don't log sensitive data like passwords
          body: this.sanitizeBody(requestInfo.body),
        },
        requestInfo.ip,
        requestInfo.userAgent,
      );
    } catch (error) {
      // Don't let audit logging break the main application
      console.error('Audit logging failed:', error);
    }
  }

  private determineAction(method: string, url: string): string {
    if (url.includes('/auth/register')) return 'USER_REGISTRATION_ATTEMPT';
    if (url.includes('/auth/login')) return 'USER_LOGIN_ATTEMPT';
    if (url.includes('/auth/logout')) return 'USER_LOGOUT';
    if (url.includes('/auth/verify-otp')) return 'OTP_VERIFICATION_ATTEMPT';
    if (url.includes('/auth/forgot-password')) return 'PASSWORD_RESET_REQUEST';
    if (url.includes('/auth/reset-password')) return 'PASSWORD_RESET_ATTEMPT';
    if (url.includes('/auth/refresh')) return 'TOKEN_REFRESH_ATTEMPT';
    if (url.includes('/users/profile')) return 'PROFILE_ACCESS';

    return `${method.toUpperCase()}_${url.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}`;
  }

  private sanitizeBody(body: unknown): unknown {
    if (!body || typeof body !== 'object') return body;

    const sanitized = { ...(body as Record<string, unknown>) };

    // Remove sensitive fields
    if (sanitized.password) sanitized.password = '[REDACTED]';
    if (sanitized.confirmPassword) sanitized.confirmPassword = '[REDACTED]';
    if (sanitized.currentPassword) sanitized.currentPassword = '[REDACTED]';
    if (sanitized.refreshToken) sanitized.refreshToken = '[REDACTED]';
    if (sanitized.token) sanitized.token = '[REDACTED]';

    return sanitized;
  }
}
