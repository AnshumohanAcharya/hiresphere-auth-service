import { Field, ObjectType } from '@nestjs/graphql';
import { User } from './user.type';

@ObjectType()
export class AuthResponse {
  @Field()
  accessToken: string;

  @Field()
  refreshToken: string;

  @Field(() => User)
  user: User;

  @Field()
  message: string;
}

@ObjectType()
export class RegisterResponse {
  @Field()
  message: string;

  @Field()
  userId: string;

  @Field()
  emailSent: boolean;
}

@ObjectType()
export class VerifyOtpResponse {
  @Field()
  message: string;

  @Field()
  isVerified: boolean;

  @Field({ nullable: true })
  accessToken?: string;

  @Field({ nullable: true })
  refreshToken?: string;
}

@ObjectType()
export class ForgotPasswordResponse {
  @Field()
  message: string;

  @Field()
  emailSent: boolean;
}

@ObjectType()
export class ResetPasswordResponse {
  @Field()
  message: string;

  @Field()
  success: boolean;
}

@ObjectType()
export class RefreshTokenResponse {
  @Field()
  accessToken: string;

  @Field()
  refreshToken: string;

  @Field()
  message: string;
}
