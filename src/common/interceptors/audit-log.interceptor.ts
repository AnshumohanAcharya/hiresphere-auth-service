import { Request, Response } from 'express';
import { Observable } from 'rxjs';
import { catchError, tap } from 'rxjs/operators';
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
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const response = context.switchToHttp().getResponse<Response>();
    const startTime = Date.now();

    // Extract request information with proper typing
    const ip = this.getClientIp(request);
    const userAgent = this.getUserAgent(request.headers);
    const method = request.method;
    const url = request.url;
    const userId = request.user?.id;
    const requestHeaders = this.sanitizeHeaders(request.headers);
    const requestBody = this.sanitizeRequestBody(request.body);

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
        responseStatus: response.statusCode,
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

  private getClientIp(request: AuthenticatedRequest): string {
    return (
      request.ip ||
      request.socket?.remoteAddress ||
      (request.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      'unknown'
    );
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
