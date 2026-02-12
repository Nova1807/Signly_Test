import { Injectable, Logger } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class AppleAuthGuard extends AuthGuard('apple') {
  private readonly logger = new Logger(AppleAuthGuard.name);

  getAuthenticateOptions(): any {
    const callbackURL =
      process.env.APPLE_CALLBACK_URL ??
      'https://backend.signly.at/auth/apple/redirect';

    const clientId = process.env.APPLE_CLIENT_ID || '';
    const teamId = process.env.APPLE_TEAM_ID || '';
    const keyId = process.env.APPLE_KEY_ID || '';
    const rawPrivateKey = process.env.APPLE_PRIVATE_KEY || '';
    const keyLength = rawPrivateKey.length;

    this.logger.log(
      `Starting Apple OAuth flow via AppleAuthGuard (callbackURL=${callbackURL}, clientID=${!!clientId}, teamID=${!!teamId}, keyID=${!!keyId}, keyLength=${keyLength})`,
    );

    return {};
  }
}
