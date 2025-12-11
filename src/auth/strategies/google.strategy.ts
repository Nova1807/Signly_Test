import { Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile, StrategyOptions } from 'passport-google-oauth20';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  private readonly logger = new Logger(GoogleStrategy.name);

  constructor() {
    const options: StrategyOptions = {
      clientID: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      callbackURL:
        process.env.GOOGLE_CALLBACK_URL ??
        'https://backend.signly.at/auth/google/redirect',
      scope: ['email', 'profile'],
    };

    super(options);

    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      this.logger.warn(
        'GoogleStrategy initialized without GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET env variables.',
      );
    }
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
  ): Promise<{ email: string; name: string; googleId: string }> {
    const email =
      profile.emails && profile.emails.length > 0
        ? profile.emails[0].value
        : '';
    const name = profile.displayName || '';
    const googleId = profile.id;

    this.logger.log(
      `validate called: email=${email}, name=${name}, googleId=${googleId}`,
    );

    return { email, name, googleId };
  }
}
