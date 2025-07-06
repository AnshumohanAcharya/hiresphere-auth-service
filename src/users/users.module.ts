import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { Module } from '@nestjs/common';
import { SecurityModule } from '../security/security.module';

@Module({
  imports: [SecurityModule],
  providers: [UsersService],
  controllers: [UsersController],
  exports: [UsersService],
})
export class UsersModule {}
