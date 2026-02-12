import { Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy as AppleStrategyLib } from 'passport-apple';

@Injectable()
export class AppleStrategy extends PassportStrategy(AppleStrategyLib, 'apple') {
  private readonly logger = new Logger(AppleStrategy.name);

  constructor() {
    // ENV lesen und prüfen BEVOR passport-apple (super) ausgeführt wird
    const rawPrivateKey = process.env.APPLE_PRIVATE_KEY || '';
    const formattedPrivateKey = rawPrivateKey.replace(/\\n/g, '\n');

    const clientID = process.env.APPLE_CLIENT_ID || '';
    const teamID = process.env.APPLE_TEAM_ID || '';
    const keyID = process.env.APPLE_KEY_ID || '';

    // Hier KEIN this benutzen – wir sind vor super()
    // Stattdessen direkt in stdout loggen, damit du es sicher im Container-Log siehst
    // eslint-disable-next-line no-console
    console.log(
      `[AppleStrategy pre-super] clientID=${!!clientID}, teamID=${!!teamID}, keyID=${!!keyID}, keyLength=${formattedPrivateKey.length}`,
    );

    if (!clientID || !teamID || !keyID || !formattedPrivateKey) {
      throw new Error(
        '[AppleStrategy] Missing required env vars. Please set APPLE_CLIENT_ID, APPLE_TEAM_ID, APPLE_KEY_ID and APPLE_PRIVATE_KEY.',
      );
    }

    const options: any = {
      clientID,
      teamID,
      keyID,
      key: formattedPrivateKey,
      callbackURL:
        process.env.APPLE_CALLBACK_URL ??
        'https://backend.signly.at/auth/apple/redirect',
      scope: ['name', 'email'],
    };

    super(options);

    this.logger.log(
      `AppleStrategy initialized with callbackURL=${options.callbackURL}`,
    );
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    idToken: any,
    profile: any,
    done: (error: any, user?: any) => void,
  ): Promise<any> {
    try {
      const email = profile?.email || '';
      const name =
        (profile?.name &&
          [profile.name.firstName, profile.name.lastName]
            .filter(Boolean)
            .join(' ')) ||
        '';
      const appleId = profile?.id;

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
