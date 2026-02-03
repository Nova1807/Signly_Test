import { Injectable, Logger } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class AppleAuthGuard extends AuthGuard('apple') {
  private readonly logger = new Logger(AppleAuthGuard.name);

  getAuthenticateOptions(): any {
    this.logger.log('Starting Apple OAuth flow via AppleAuthGuard');
    return {};
  }
}
