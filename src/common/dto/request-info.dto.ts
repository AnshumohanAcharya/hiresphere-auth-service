import { ApiProperty } from '@nestjs/swagger';

export class RequestInfoDto {
  @ApiProperty({ description: 'Client IP address' })
  ip: string;

  @ApiProperty({ description: 'User agent string' })
  userAgent: string;

  @ApiProperty({ description: 'Request method' })
  method: string;

  @ApiProperty({ description: 'Request URL' })
  url: string;

  @ApiProperty({ description: 'Request headers' })
  headers: Record<string, string>;
}
