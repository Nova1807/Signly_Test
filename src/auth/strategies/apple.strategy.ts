import { Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import AppleStrategyLib from 'passport-apple';

@Injectable()
export class AppleStrategy extends PassportStrategy(AppleStrategyLib, 'apple') {
  private readonly logger = new Logger(AppleStrategy.name);

  constructor() {
    const options: any = {
      clientID: process.env.APPLE_CLIENT_ID || '',
      teamID: process.env.APPLE_TEAM_ID || '',
      keyID: process.env.APPLE_KEY_ID || '',
      key: process.env.APPLE_PRIVATE_KEY || '',
      callbackURL:
        process.env.APPLE_CALLBACK_URL ??
        'https://backend.signly.at/auth/apple/redirect',
      scope: ['name', 'email'],
    };

    super(options);

    if (!options.clientID || !options.teamID || !options.keyID || !options.key) {
      this.logger.warn(
        'AppleStrategy initialized without full Apple env configuration (APPLE_CLIENT_ID, APPLE_TEAM_ID, APPLE_KEY_ID, APPLE_PRIVATE_KEY).',
      );
    }
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: (error: any, user?: any) => void,
  ): Promise<any> {
    try {
      const email = profile.email || '';
      const name =
        (profile.name &&
          [profile.name.firstName, profile.name.lastName]
            .filter(Boolean)
            .join(' ')) ||
        '';
      const appleId = profile.id;

      this.logger.log(
        `Apple validate called: email=${email}, name=${name}, appleId=${appleId}`,
      );

      const user = { email, name, appleId };
      done(null, user);
      return user;
    } catch (error) {
      this.logger.error(`Apple validate error: ${error?.message}`, error?.stack);
      done(error, null);
      throw error;
    }
  }
}
