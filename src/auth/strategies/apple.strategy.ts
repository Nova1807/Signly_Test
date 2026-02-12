import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { Strategy as AppleStrategyLib } from 'passport-apple';
import jwt, { JwtPayload } from 'jsonwebtoken';

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
      passReqToCallback: true,
    };

    super(options);

    this.logger.log(
      `AppleStrategy initialized with callbackURL=${options.callbackURL}`,
    );
  }

  async validate(
    req: Request,
    accessToken: string,
    refreshToken: string,
    params: Record<string, any> | string | undefined,
    profile: any,
    done: (error: any, user?: any) => void,
  ): Promise<any> {
    try {
      const appleProfile = (req as any)?.appleProfile as
        | { email?: string; name?: { firstName?: string; lastName?: string } }
        | undefined;

      const idToken =
        (typeof params === 'string' ? params : params?.id_token) ||
        (req.body as any)?.id_token;
      if (!idToken) {
        const error = new BadRequestException('Apple callback is missing id_token');
        this.logger.error('Apple validate error: missing id_token in Apple response');
        done(error, null);
        throw error;
      }

      const decoded = jwt.decode(idToken, { json: true }) as
        | (JwtPayload & {
            email?: string;
            email_verified?: string | boolean;
            sub?: string;
          })
        | null;

      if (!decoded) {
        const error = new BadRequestException('Unable to decode Apple id_token');
        this.logger.error('Apple validate error: could not decode id_token');
        done(error, null);
        throw error;
      }

      const email = appleProfile?.email || (decoded.email as string) || '';
      const name =
        (appleProfile?.name &&
          [appleProfile.name.firstName, appleProfile.name.lastName]
            .filter(Boolean)
            .join(' ')) ||
        '';
      const appleId = (decoded.sub as string) || '';

      if (!appleId) {
        const error = new BadRequestException('Apple id_token has no subject (appleId)');
        this.logger.warn('Apple validate error: id_token has no sub');
        done(error, null);
        throw error;
      }

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
