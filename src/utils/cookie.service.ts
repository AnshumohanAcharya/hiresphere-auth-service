import { Injectable } from '@nestjs/common';
import { Response } from 'express';

export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  maxAge?: number;
  domain?: string;
  path?: string;
}

@Injectable()
export class CookieService {
  private response: Response | null = null;

  setResponse(response: Response): void {
    this.response = response;
  }

  setCookie(name: string, value: string, options: CookieOptions = {}): void {
    if (!this.response) {
      throw new Error('Response object not set. Call setResponse() first.');
    }

    const cookieOptions: CookieOptions = {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/',
      ...options,
    };

    this.response.cookie(name, value, cookieOptions);
  }

  clearCookie(name: string, options: CookieOptions = {}): void {
    if (!this.response) {
      throw new Error('Response object not set. Call setResponse() first.');
    }

    const cookieOptions: CookieOptions = {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/',
      maxAge: 0,
      ...options,
    };

    this.response.clearCookie(name, cookieOptions);
  }

  getCookie(name: string): string | undefined {
    if (!this.response) {
      throw new Error('Response object not set. Call setResponse() first.');
    }

    const cookies = (this.response.req as any).cookies;
    const value = cookies?.[name];
    return typeof value === 'string' ? value : undefined;
  }
}
