import { Module } from '@nestjs/common';
import { SignsService } from './signs.service';
import { SignsController } from './signs.controller';

@Module({
  providers: [SignsService],
  controllers: [SignsController],
  exports: [SignsService],
})
export class SignsModule {}
