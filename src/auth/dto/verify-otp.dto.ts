import {
  IsString,
  IsNotEmpty,
  Length,
  IsEnum,
  Matches,
  IsEmail,
} from 'class-validator';

import { ApiProperty } from '@nestjs/swagger';
import { OtpType } from '@prisma/client';

export class VerifyOtpDto {
  @ApiProperty({
    description: 'Email address associated with the OTP',
    example: 'user@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    description: 'OTP code',
    example: '123456',
    minLength: 6,
    maxLength: 6,
  })
  @IsString()
  @IsNotEmpty()
  @Length(6, 6, { message: 'OTP must be exactly 6 digits' })
  @Matches(/^\d{6}$/, { message: 'OTP must contain only digits' })
  code: string;

  @ApiProperty({
    description: 'Type of OTP',
    enum: OtpType,
    example: OtpType.EMAIL_VERIFICATION,
  })
  @IsEnum(OtpType)
  type: OtpType;
}
