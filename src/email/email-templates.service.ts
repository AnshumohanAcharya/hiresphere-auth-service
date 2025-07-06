import { Injectable } from '@nestjs/common';

@Injectable()
export class EmailTemplatesService {
  generateOtpEmail(firstName: string, otp: string, type: string): string {
    const purpose = this.getOtpPurpose(type);

    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verification Code - HireSphere</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #2563eb; color: white; padding: 20px; text-align: center; }
          .content { padding: 30px; background: #f9fafb; }
          .otp-code { font-size: 32px; font-weight: bold; text-align: center; color: #2563eb; padding: 20px; background: white; border-radius: 8px; margin: 20px 0; }
          .footer { text-align: center; padding: 20px; color: #6b7280; font-size: 14px; }
          .warning { background: #fef3c7; border: 1px solid #f59e0b; padding: 15px; border-radius: 8px; margin: 20px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>HireSphere</h1>
          </div>
          <div class="content">
            <h2>Hello ${firstName}!</h2>
            <p>You requested a verification code for ${purpose}.</p>
            <p>Here's your verification code:</p>
            <div class="otp-code">${otp}</div>
            <p>This code will expire in 5 minutes.</p>
            <div class="warning">
              <strong>Security Notice:</strong> Never share this code with anyone. HireSphere will never ask for this code via phone, email, or text message.
            </div>
            <p>If you didn't request this code, please ignore this email or contact our support team.</p>
          </div>
          <div class="footer">
            <p>&copy; 2024 HireSphere. All rights reserved.</p>
            <p>This is an automated message, please do not reply to this email.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  generatePasswordResetEmail(firstName: string, resetUrl: string): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset Your Password - HireSphere</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #2563eb; color: white; padding: 20px; text-align: center; }
          .content { padding: 30px; background: #f9fafb; }
          .button { display: inline-block; background: #2563eb; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; margin: 20px 0; }
          .footer { text-align: center; padding: 20px; color: #6b7280; font-size: 14px; }
          .warning { background: #fef3c7; border: 1px solid #f59e0b; padding: 15px; border-radius: 8px; margin: 20px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>HireSphere</h1>
          </div>
          <div class="content">
            <h2>Hello ${firstName}!</h2>
            <p>We received a request to reset your password for your HireSphere account.</p>
            <p>Click the button below to reset your password:</p>
            <div style="text-align: center;">
              <a href="${resetUrl}" class="button">Reset Password</a>
            </div>
            <p>This link will expire in 1 hour for security reasons.</p>
            <div class="warning">
              <strong>Security Notice:</strong> If you didn't request this password reset, please ignore this email. Your password will remain unchanged.
            </div>
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #2563eb;">${resetUrl}</p>
          </div>
          <div class="footer">
            <p>&copy; 2024 HireSphere. All rights reserved.</p>
            <p>This is an automated message, please do not reply to this email.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  generateWelcomeEmail(firstName: string): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to HireSphere!</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #2563eb; color: white; padding: 20px; text-align: center; }
          .content { padding: 30px; background: #f9fafb; }
          .footer { text-align: center; padding: 20px; color: #6b7280; font-size: 14px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Welcome to HireSphere!</h1>
          </div>
          <div class="content">
            <h2>Hello ${firstName}!</h2>
            <p>Welcome to HireSphere! We're excited to have you on board.</p>
            <p>Your account has been successfully created and your email has been verified.</p>
            <p>You can now:</p>
            <ul>
              <li>Complete your profile</li>
              <li>Browse job opportunities</li>
              <li>Connect with employers</li>
              <li>Track your applications</li>
            </ul>
            <p>If you have any questions or need assistance, don't hesitate to contact our support team.</p>
            <p>Best regards,<br>The HireSphere Team</p>
          </div>
          <div class="footer">
            <p>&copy; 2024 HireSphere. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  private getOtpPurpose(type: string): string {
    switch (type) {
      case 'EMAIL_VERIFICATION':
        return 'email verification';
      case 'PASSWORD_RESET':
        return 'password reset';
      case 'LOGIN_VERIFICATION':
        return 'login verification';
      default:
        return 'verification';
    }
  }
}
