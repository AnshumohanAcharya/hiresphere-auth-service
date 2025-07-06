import { IsEmail, IsNotEmpty, IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { OtpType } from '@prisma/client';

export class ResendOtpDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
  })
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    description: 'Type of OTP to resend',
    enum: OtpType,
    example: OtpType.EMAIL_VERIFICATION,
  })
  @IsEnum(OtpType)
  type: OtpType;
}
