import * as nodemailer from 'nodemailer';
import { SentMessageInfo } from 'nodemailer';

import { EmailTemplatesService } from './email-templates.service';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export interface EmailConfig {
  host: string;
  port: number;
  secure: boolean;
  auth: {
    user: string;
    pass: string;
  };
  tls?: {
    rejectUnauthorized: boolean;
  };
}

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;
  constructor(
    private readonly configService: ConfigService,
    private readonly emailTemplatesService: EmailTemplatesService,
  ) {
    this.initializeTransporter();
  }

  private initializeTransporter(): void {
    const config: EmailConfig = {
      host: this.configService.get<string>('EMAIL_HOST', 'smtp.gmail.com'),
      port: this.configService.get<number>('EMAIL_PORT', 587),
      secure: false, // Use STARTTLS for Gmail
      auth: {
        user: this.configService.get<string>('EMAIL_USER', ''),
        pass: this.configService.get<string>('EMAIL_PASS', ''),
      },
    };

    this.transporter = nodemailer.createTransport(config);
    this.logger.log(
      `Email service initialized with host: ${config.host}:${config.port}`,
    );
  }

  async sendEmail(
    to: string,
    subject: string,
    html: string,
    text?: string,
  ): Promise<SentMessageInfo> {
    try {
      const mailOptions = {
        from: this.configService.get<string>(
          'EMAIL_FROM',
          'noreply@hiresphere.com',
        ),
        to,
        subject,
        html,
        text,
      };

      const result = await this.transporter.sendMail(mailOptions);
      this.logger.log(`Email sent successfully to ${to}`, result.messageId);
      return result;
    } catch (error: unknown) {
      this.logger.error(`Failed to send email to ${to}`, error);
      throw error;
    }
  }

  async sendOtpEmail(
    to: string,
    firstName: string,
    otp: string,
    type: string,
  ): Promise<void> {
    const subject = this.getOtpSubject(type);
    const html = this.getOtpHtml(firstName, otp, type);
    const text = this.getOtpText(firstName, otp, type);

    await this.sendEmail(to, subject, html, text);
  }

  async sendWelcomeEmail(to: string, firstName: string): Promise<void> {
    const subject = 'Welcome to HireSphere!';
    const html = this.getWelcomeHtml(firstName);
    const text = this.getWelcomeText(firstName);

    await this.sendEmail(to, subject, html, text);
  }

  private getOtpSubject(type: string): string {
    switch (type) {
      case 'EMAIL_VERIFICATION':
        return 'Verify Your Email - HireSphere';
      case 'PASSWORD_RESET':
        return 'Reset Your Password - HireSphere';
      default:
        return 'Your Verification Code - HireSphere';
    }
  }

  private getOtpHtml(firstName: string, otp: string, type: string): string {
    const action =
      type === 'EMAIL_VERIFICATION'
        ? 'verify your email'
        : 'reset your password';

    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Hello ${firstName}!</h2>
        <p>Your verification code to ${action} is:</p>
        <div style="background-color: #f4f4f4; padding: 20px; text-align: center; margin: 20px 0;">
          <h1 style="color: #007bff; font-size: 32px; margin: 0; letter-spacing: 5px;">${otp}</h1>
        </div>
        <p>This code will expire in 10 minutes.</p>
        <p>If you didn't request this code, please ignore this email.</p>
        <hr>
        <p style="color: #666; font-size: 12px;">
          This is an automated message from HireSphere. Please do not reply to this email.
        </p>
      </div>
    `;
  }

  private getOtpText(firstName: string, otp: string, type: string): string {
    const action =
      type === 'EMAIL_VERIFICATION'
        ? 'verify your email'
        : 'reset your password';

    return `
Hello ${firstName}!

Your verification code to ${action} is: ${otp}

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email.

---
This is an automated message from HireSphere. Please do not reply to this email.
    `;
  }

  private getWelcomeHtml(firstName: string): string {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Welcome to HireSphere, ${firstName}!</h2>
        <p>Thank you for joining HireSphere. Your account has been successfully verified.</p>
        <p>You can now:</p>
        <ul>
          <li>Complete your profile</li>
          <li>Browse job opportunities</li>
          <li>Connect with employers</li>
          <li>Track your applications</li>
        </ul>
        <p>If you have any questions, feel free to contact our support team.</p>
        <hr>
        <p style="color: #666; font-size: 12px;">
          Welcome to the HireSphere community!
        </p>
      </div>
    `;
  }

  private getWelcomeText(firstName: string): string {
    return `
Welcome to HireSphere, ${firstName}!

Thank you for joining HireSphere. Your account has been successfully verified.

You can now:
- Complete your profile
- Browse job opportunities
- Connect with employers
- Track your applications

If you have any questions, feel free to contact our support team.

---
Welcome to the HireSphere community!
    `;
  }

  async verifyEmailConfiguration(): Promise<boolean> {
    try {
      await this.transporter.verify();
      this.logger.log('Email configuration is valid');
      return true;
    } catch (error) {
      this.logger.error('Email configuration is invalid:', error);
      return false;
    }
  }
}
