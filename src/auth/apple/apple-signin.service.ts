import {
  BadRequestException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import * as https from 'node:https';
import { createPublicKey, randomBytes } from 'node:crypto';
import jwt, { JwtPayload } from 'jsonwebtoken';

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

type AppleCallbackPayload = {
  idToken?: string;
  state?: string;
  user?: string | Record<string, any>;
};

type AppleProfile = {
  appleId: string;
  email: string;
  name: string;
};

type AppleStatePayload = {
  nonce: string;
  iat: number;
  exp: number;
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
  private static readonly APPLE_AUTH_URL = 'https://appleid.apple.com/auth/authorize';
  private appleKeysCache:
    | {
        keys: ApplePublicKey[];
        fetchedAt: number;
      }
    | null = null;

  getAuthorizationUrl(): string {
    const state = this.generateStateToken();
    const params = new URLSearchParams({
      response_type: 'code id_token',
      response_mode: 'form_post',
      scope: 'name email',
      client_id: this.getClientId(),
      redirect_uri: this.getCallbackUrl(),
      state,
    });

    const url = `${AppleSignInService.APPLE_AUTH_URL}?${params.toString()}`;
    this.logger.log(`Apple authorization URL generated with state token`);
    return url;
  }

  extractCallbackPayload(req: Request): AppleCallbackPayload {
    const body = req.body ?? {};
    const query = req.query ?? {};

    const idToken =
      (body as any)?.id_token ||
      (body as any)?.idToken ||
      (query as any)?.id_token ||
      (query as any)?.idToken;
    const state = (body as any)?.state || (query as any)?.state;
    const user = (body as any)?.user || (query as any)?.user;

    return {
      idToken: typeof idToken === 'string' ? idToken : undefined,
      state: typeof state === 'string' ? state : undefined,
      user: user,
    };
  }

  async buildProfileFromPayload(payload: AppleCallbackPayload): Promise<AppleProfile> {
    const stateData = this.verifyStateToken(payload.state);
    const idToken = payload.idToken;

    if (!idToken) {
      throw new BadRequestException('Missing id_token from Apple callback');
    }

    const decoded = await this.verifyAndDecodeIdToken(idToken);
    const parsedUser = this.parseUserField(payload.user);

    const email = parsedUser.email || decoded.email || '';
    const name = parsedUser.name || '';
    const appleId = decoded.sub;

    if (!appleId) {
      throw new UnauthorizedException('Apple id_token does not contain a subject');
    }

    this.logger.log(
      `Verified Apple id_token for appleId=${appleId}, email=${email || 'n/a'}, stateNonce=${
        stateData.nonce
      }`,
    );

    return {
      appleId,
      email,
      name,
    };
  }

  private getClientId(): string {
    const value = process.env.APPLE_CLIENT_ID;
    if (!value) {
      throw new Error('APPLE_CLIENT_ID env variable is not configured');
    }
    return value;
  }

  private getCallbackUrl(): string {
    return (
      process.env.APPLE_CALLBACK_URL ?? 'https://backend.signly.at/auth/apple/redirect'
    );
  }

  private getStateSecret(): string {
    return process.env.APPLE_STATE_SECRET || process.env.JWT_SECRET || 'apple-state-dev';
  }

  private generateStateToken(): string {
    const payload = {
      nonce: randomBytes(16).toString('hex'),
    };

    return jwt.sign(payload, this.getStateSecret(), { expiresIn: '10m' });
  }

  private verifyStateToken(state: string | undefined): AppleStatePayload {
    if (!state) {
      this.logger.warn('Apple callback missing state parameter');
      throw new UnauthorizedException('Missing Apple state parameter');
    }

    try {
      return jwt.verify(state, this.getStateSecret()) as AppleStatePayload;
    } catch (err: any) {
      this.logger.warn(`Invalid Apple state token: ${err?.message}`);
      throw new UnauthorizedException('Invalid Apple state parameter');
    }
  }

  private parseUserField(userField: AppleCallbackPayload['user']): {
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
