import {
  BadRequestException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import * as https from 'node:https';
import { createPublicKey } from 'node:crypto';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { formatLogContext, maskEmail, maskId } from '../../common/logging/redaction';

type ApplePublicKey = {
  kty: string;
  kid: string;
  use: string;
  alg: string;
  n: string;
  e: string;
};

type AppleKeysResponse = {
  keys: ApplePublicKey[];
};

type AppleAppPayload = {
  identityToken?: string;
  user?: string | Record<string, any>;
  email?: string;
  fullName?: string;
  firstName?: string;
  lastName?: string;
};

type AppleProfile = {
  appleId: string;
  email: string;
  name: string;
};

type AppleUserField = {
  email?: string;
  name?: {
    firstName?: string;
    lastName?: string;
  };
};

type AppleIdTokenPayload = JwtPayload & {
  sub: string;
  email?: string;
  email_verified?: string | boolean;
  is_private_email?: string;
};

@Injectable()
export class AppleSignInService {
  private readonly logger = new Logger(AppleSignInService.name);
  private static readonly APPLE_KEYS_URL = 'https://appleid.apple.com/auth/keys';
  private appleKeysCache:
    | {
        keys: ApplePublicKey[];
        fetchedAt: number;
      }
    | null = null;

  async buildProfileFromAppPayload(payload: AppleAppPayload): Promise<AppleProfile> {
    const fallbackName = this.buildNameFromParts(payload);
    return this.buildProfileFromIdToken({
      idToken: payload.identityToken,
      user: payload.user,
      fallbackEmail: payload.email,
      fallbackName,
      logSuffix: 'app-flow',
    });
  }

  private getClientId(): string {
    const value = process.env.APPLE_CLIENT_ID;
    if (!value) {
      throw new Error('APPLE_CLIENT_ID env variable is not configured');
    }
    return value;
  }

  private parseUserField(userField: AppleAppPayload['user']): {
    email: string;
    name: string;
  } {
    if (!userField) {
      return { email: '', name: '' };
    }

    let parsed: AppleUserField | null = null;

    if (typeof userField === 'string') {
      try {
        parsed = JSON.parse(userField) as AppleUserField;
      } catch (err: any) {
        this.logger.warn(`Failed to parse Apple user payload: ${err?.message}`);
        parsed = null;
      }
    } else if (typeof userField === 'object') {
      parsed = userField as AppleUserField;
    }

    if (!parsed) {
      return { email: '', name: '' };
    }

    const nameParts: string[] = [];
    if (parsed.name?.firstName) nameParts.push(parsed.name.firstName);
    if (parsed.name?.lastName) nameParts.push(parsed.name.lastName);

    return {
      email: parsed.email || '',
      name: nameParts.join(' ').trim(),
    };
  }

  private buildNameFromParts(payload: {
    fullName?: string;
    firstName?: string;
    lastName?: string;
  }): string {
    const nameParts: string[] = [];
    if (payload.firstName) {
      nameParts.push(payload.firstName);
    }
    if (payload.lastName) {
      nameParts.push(payload.lastName);
    }

    const joined = nameParts.join(' ').trim();
    if (joined) {
      return joined;
    }
    return payload.fullName?.trim() || '';
  }

  private async buildProfileFromIdToken(options: {
    idToken?: string;
    user?: AppleAppPayload['user'];
    fallbackEmail?: string;
    fallbackName?: string;
    logSuffix?: string;
  }): Promise<AppleProfile> {
    if (!options.idToken) {
      throw new BadRequestException('Missing id_token from Apple login');
    }

    const decoded = await this.verifyAndDecodeIdToken(options.idToken);
    const parsedUser = this.parseUserField(options.user);

    const email = parsedUser.email || options.fallbackEmail || decoded.email || '';
    const name = parsedUser.name || options.fallbackName || '';
    const appleId = decoded.sub;

    if (!appleId) {
      throw new UnauthorizedException('Apple id_token does not contain a subject');
    }

    const logSuffix = options.logSuffix ? `, ${options.logSuffix}` : '';
    this.logger.log(
      'Verified Apple id_token' +
        formatLogContext({
          appleId: maskId(appleId),
          email: maskEmail(email),
          logSuffix,
        }),
    );

    return {
      appleId,
      email,
      name,
    };
  }

  private async verifyAndDecodeIdToken(idToken: string): Promise<AppleIdTokenPayload> {
    const decodedHeader = jwt.decode(idToken, { complete: true });

    if (!decodedHeader || typeof decodedHeader !== 'object') {
      throw new UnauthorizedException('Unable to decode Apple id_token header');
    }

    const kid = (decodedHeader.header as any)?.kid;
    if (!kid) {
      throw new UnauthorizedException('Apple id_token header missing key id');
    }

    const appleKey = await this.findApplePublicKey(kid);
    const pem = createPublicKey({
      key: {
        kty: appleKey.kty,
        n: appleKey.n,
        e: appleKey.e,
      },
      format: 'jwk',
    })
      .export({ format: 'pem', type: 'spki' })
      .toString();

    try {
      const payload = jwt.verify(idToken, pem, {
        algorithms: ['RS256'],
        issuer: 'https://appleid.apple.com',
        audience: this.getClientId(),
      }) as AppleIdTokenPayload;

      return payload;
    } catch (err: any) {
      this.logger.error(`Failed to verify Apple id_token: ${err?.message}`, err?.stack);
      throw new UnauthorizedException('Invalid Apple identity token');
    }
  }

  private async findApplePublicKey(kid: string): Promise<ApplePublicKey> {
    const keys = await this.getApplePublicKeys();
    const key = keys.find((k) => k.kid === kid);
    if (!key) {
      throw new UnauthorizedException('Apple signing key not found');
    }
    return key;
  }

  private async getApplePublicKeys(): Promise<ApplePublicKey[]> {
    const cacheLifetimeMs = 6 * 60 * 60 * 1000; // 6 hours
    if (
      this.appleKeysCache &&
      Date.now() - this.appleKeysCache.fetchedAt < cacheLifetimeMs
    ) {
      return this.appleKeysCache.keys;
    }

    const response = await this.fetchJson<AppleKeysResponse>(
      AppleSignInService.APPLE_KEYS_URL,
    );

    if (!response?.keys?.length) {
      throw new UnauthorizedException('Apple returned no signing keys');
    }

    this.appleKeysCache = {
      keys: response.keys,
      fetchedAt: Date.now(),
    };

    return response.keys;
  }

  private fetchJson<T>(url: string): Promise<T> {
    return new Promise((resolve, reject) => {
      https
        .get(url, (res) => {
          if (!res.statusCode) {
            reject(new Error('Apple keys response has no status code'));
            return;
          }

          if (res.statusCode >= 400) {
            reject(
              new Error(`Apple keys request failed with status ${res.statusCode}`),
            );
            return;
          }

          const chunks: Buffer[] = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('end', () => {
            try {
              const raw = Buffer.concat(chunks).toString('utf8');
              resolve(JSON.parse(raw));
            } catch (err) {
              reject(err);
            }
          });
        })
        .on('error', (err) => reject(err));
    });
  }
}
