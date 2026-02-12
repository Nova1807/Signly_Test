import { Injectable, Logger } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class AppleAuthGuard extends AuthGuard('apple') {
  private readonly logger = new Logger(AppleAuthGuard.name);

  getAuthenticateOptions(): any {
    const callbackURL =
      process.env.APPLE_CALLBACK_URL ??
      'https://backend.signly.at/auth/apple/redirect';

    this.logger.log(
      `Starting Apple OAuth flow via AppleAuthGuard (callbackURL=${callbackURL})`,
    );

    return {};
  }
}
