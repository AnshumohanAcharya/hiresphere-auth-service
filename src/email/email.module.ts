import { EmailTemplatesService } from './email-templates.service';
import { Module } from '@nestjs/common';
import { EmailService } from './email.service';

@Module({
  providers: [EmailService, EmailTemplatesService],
  exports: [EmailService],
})
export class EmailModule {}
