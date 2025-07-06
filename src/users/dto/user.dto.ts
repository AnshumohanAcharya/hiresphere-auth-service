import { ApiProperty } from '@nestjs/swagger';

export class UserResponseDto {
  @ApiProperty({ description: 'User ID' })
  id: string;

  @ApiProperty({ description: 'User email' })
  email: string;

  @ApiProperty({ description: 'User first name' })
  firstName: string;

  @ApiProperty({ description: 'User last name' })
  lastName: string;

  @ApiProperty({ description: 'Whether email is verified' })
  isEmailVerified: boolean;

  @ApiProperty({ description: 'Whether user is active' })
  isActive: boolean;

  @ApiProperty({ description: 'User creation date' })
  createdAt: Date;

  @ApiProperty({ description: 'User last update date' })
  updatedAt: Date;
}
