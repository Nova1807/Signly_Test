import { BadRequestException, Logger, UnauthorizedException } from '@nestjs/common';
import * as admin from 'firebase-admin';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { LoginDto } from '../dto/login.dto';
import {
  formatLogContext,
  hasValue,
  maskEmail,
  maskId,
  maskIdentifier,
  maskToken,
} from '../../common/logging/redaction';
import { UserCollectionsManager } from './user-collections.manager';

export interface SessionManagerOptions {
  firebaseApp: admin.app.App;
  logger: Logger;
  jwtService: JwtService;
  userCollectionsManager: UserCollectionsManager;
  refreshTokenCleanupBatchSize?: number;
}

export class SessionManager {
  private readonly refreshTokenCleanupBatchSize: number;
  private readonly loginStreakDateFormatter: Intl.DateTimeFormat;

  constructor(private readonly options: SessionManagerOptions) {
    this.refreshTokenCleanupBatchSize = Math.max(
      1,
      Number.isFinite(options.refreshTokenCleanupBatchSize)
        ? Number(options.refreshTokenCleanupBatchSize)
        : 500,
    );

    const configuredTimeZone =
      process.env.LOGIN_STREAK_TIMEZONE || process.env.TZ || 'Europe/Vienna';

    const { formatter } = this.createLoginStreakFormatter(configuredTimeZone);
    this.loginStreakDateFormatter = formatter;
  }

  private get firestore() {
    return this.options.firebaseApp.firestore();
  }

  private get jwtService() {
    return this.options.jwtService;
  }

  private get logger() {
    return this.options.logger;
  }

  private createLoginStreakFormatter(
    configuredTimeZone: string,
  ): { formatter: Intl.DateTimeFormat } {
    const fallbackTimeZone = 'UTC';
    try {
      const formatter = new Intl.DateTimeFormat('en-CA', {
        timeZone: configuredTimeZone,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
      });
      // Format once to ensure the timezone is valid up front.
      formatter.format(new Date());
      this.logger.log(
        'login streak timezone configured' + formatLogContext({ timeZone: configuredTimeZone }),
      );
      return { formatter };
    } catch (err: any) {
      this.logger.warn(
        'login streak timezone invalid, falling back to UTC' +
          formatLogContext({
            configuredTimeZone,
            fallback: fallbackTimeZone,
            error: err?.message,
          }),
      );
      return {
        formatter: new Intl.DateTimeFormat('en-CA', {
          timeZone: fallbackTimeZone,
          year: 'numeric',
          month: '2-digit',
          day: '2-digit',
        }),
      };
    }
  }

  private formatDateForLoginStreak(date: Date): string {
    return this.loginStreakDateFormatter.format(date);
  }

  private parseStoredLoginDate(dateString: string): Date {
    return new Date(`${dateString}T00:00:00Z`);
  }

  private updateLoginStreak(
    user: any,
    now: Date,
  ): { loginStreak: number; longestLoginStreak: number; lastLoginDate: string } {
    const currentDate = this.formatDateForLoginStreak(now);
    const currentDateValue = this.parseStoredLoginDate(currentDate);

    const last = user.lastLoginDate as string | undefined;
    const lastDate = last ? this.parseStoredLoginDate(last) : undefined;
    let loginStreak = user.loginStreak as number | undefined;
    let longestLoginStreak = user.longestLoginStreak as number | undefined;

    if (!lastDate) {
      loginStreak = 1;
    } else {
      const diffDays = Math.floor(
        (currentDateValue.getTime() - lastDate.getTime()) / (1000 * 60 * 60 * 24),
      );

      if (diffDays === 0) {
        loginStreak = loginStreak || 1;
      } else if (diffDays === 1) {
        loginStreak = (loginStreak || 0) + 1;
      } else {
        loginStreak = 1;
      }
    }

    longestLoginStreak = Math.max(longestLoginStreak || 0, loginStreak || 0);

    return {
      loginStreak,
      longestLoginStreak,
      lastLoginDate: currentDate,
    };
  }

  async ensureLoginStreakIsCurrent(
    userId: string,
    now: Date = new Date(),
  ): Promise<{ loginStreak: number; longestLoginStreak: number; lastLoginDate: string } | null> {
    const firestore = this.firestore;
    const userRef = firestore.collection('users').doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      this.logger.warn(
        'updateLoginStreakForUserId: user document missing' +
          formatLogContext({
            userId: maskId(userId),
          }),
      );
      return null;
    }

    await this.options.userCollectionsManager.ensureUserCollections(userDoc);
    const user = userDoc.data() as any;
    const streakData = this.updateLoginStreak(user, now);

    const hasChanges =
      user?.lastLoginDate !== streakData.lastLoginDate ||
      (user?.loginStreak ?? 0) !== (streakData.loginStreak ?? 0) ||
      (user?.longestLoginStreak ?? 0) !== (streakData.longestLoginStreak ?? 0);

    if (hasChanges) {
      await userRef.update({ ...streakData });
      this.logger.log(
        'updateLoginStreakForUserId: streak updated' +
          formatLogContext({
            userId: maskId(userId),
            loginStreak: streakData.loginStreak,
            longestLoginStreak: streakData.longestLoginStreak,
          }),
      );
    }

    return streakData;
  }

  async login(credentials: LoginDto) {
    const { identifier, password } = credentials as any;

    this.logger.log(
      'login start' +
        formatLogContext({
          identifier: maskIdentifier(identifier),
          hasPassword: hasValue(password),
        }),
    );

    try {
      const firestore = this.firestore;
      this.logger.log('login: got firestore instance');

      const isEmail = typeof identifier === 'string' && identifier.includes('@');

      const userQuery = isEmail
        ? firestore.collection('users').where('email', '==', identifier)
        : firestore.collection('users').where('name', '==', identifier);

      const snapshot = await userQuery.get();
      this.logger.log(
        'login: query result' +
          formatLogContext({
            lookup: isEmail ? 'email' : 'name',
            identifier: maskIdentifier(identifier),
            matches: snapshot.size,
          }),
      );

      if (snapshot.empty) {
        this.logger.warn(
          'login: no user found' +
            formatLogContext({
              lookup: isEmail ? 'email' : 'name',
              identifier: maskIdentifier(identifier),
            }),
        );
        throw new UnauthorizedException('Wrong credentials');
      }

      const userDoc = snapshot.docs[0];
      await this.options.userCollectionsManager.ensureUserCollections(userDoc);
      const user = userDoc.data() as any;
      this.logger.log(
        'login: user document hydrated' +
          formatLogContext({
            userId: maskId(userDoc.id),
          }),
      );

      const passwordMatch = await bcrypt.compare(password, user.password);
      this.logger.log(`login: passwordMatch=${passwordMatch}`);

      if (!passwordMatch) {
        this.logger.warn(
          'login: wrong password' +
            formatLogContext({
              lookup: isEmail ? 'email' : 'name',
              identifier: maskIdentifier(identifier),
            }),
        );
        throw new UnauthorizedException('Wrong credentials');
      }

      const now = new Date();
      const streakData = this.updateLoginStreak(user, now);

      await userDoc.ref.update({
        ...streakData,
      });

      const tokens = await this.generateUserToken(userDoc.id);
      this.logger.log('login: tokens generated');

      return {
        ...tokens,
        loginStreak: streakData.loginStreak,
        longestLoginStreak: streakData.longestLoginStreak,
      };
    } catch (err) {
      this.logger.error(`login internal error: ${err?.message}`, err?.stack);
      throw err;
    }
  }

  async refreshTokens(refreshToken: string) {
    this.logger.log(
      'refreshTokens start' +
        formatLogContext({
          token: maskToken(refreshToken, 'refreshToken'),
        }),
    );

    try {
      await this.cleanupExpiredRefreshTokens();
      const firestore = this.firestore;
      this.logger.log('refreshTokens: got firestore instance');

      const tokenRef = firestore
        .collection('refreshTokens')
        .where('token', '==', refreshToken)
        .where('expiryDate', '>=', new Date());

      const snapshot = await tokenRef.get();
      this.logger.log(
        'refreshTokens: lookup result' +
          formatLogContext({
            tokens: snapshot.size,
          }),
      );

      if (snapshot.empty) {
        this.logger.warn('refreshTokens: token not found or expired');
        throw new UnauthorizedException();
      }

      const tokenDoc = snapshot.docs[0];
      const token = tokenDoc.data() as any;
      this.logger.log(
        'refreshTokens: token resolved' +
          formatLogContext({
            tokenId: maskId(tokenDoc.id),
            userId: maskId(token.userId),
          }),
      );

      try {
        await this.ensureLoginStreakIsCurrent(token.userId, new Date());
      } catch (err: any) {
        this.logger.error(
          'refreshTokens: failed to update login streak during refresh' +
            formatLogContext({
              userId: maskId(token.userId),
              error: err?.message,
            }),
          err?.stack,
        );
      }

      const tokens = await this.generateUserToken(token.userId);
      this.logger.log('refreshTokens: new tokens generated');
      return tokens;
    } catch (err) {
      this.logger.error(`refreshTokens internal error: ${err?.message}`, err?.stack);
      throw err;
    }
  }

  async generateUserToken(userId: string) {
    this.logger.log(
      'generateUserToken start' +
        formatLogContext({
          userId: maskId(userId),
        }),
    );

    const accessToken = this.jwtService.sign({ userId }, { expiresIn: '1h' });
    const refreshToken = uuidv4();
    this.logger.log('generateUserToken: tokens created');

    await this.storeRefreshToken(refreshToken, userId);
    this.logger.log('generateUserToken: refresh token stored');

    return {
      accessToken,
      refreshToken,
    };
  }

  async storeRefreshToken(token: string, userId: string) {
    this.logger.log(
      'storeRefreshToken start' +
        formatLogContext({
          userId: maskId(userId),
        }),
    );

    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);

    const firestore = this.firestore;
    this.logger.log('storeRefreshToken: got firestore instance');

    await this.cleanupExpiredRefreshTokens();
    await firestore.collection('refreshTokens').add({
      token,
      userId,
      expiryDate: admin.firestore.Timestamp.fromDate(expiryDate),
    });
    this.logger.log('storeRefreshToken: refresh token document created');
  }

  private async cleanupExpiredRefreshTokens() {
    const firestore = this.firestore;
    const now = admin.firestore.Timestamp.fromDate(new Date());
    let deletedTotal = 0;

    while (true) {
      const snapshot = await firestore
        .collection('refreshTokens')
        .where('expiryDate', '<=', now)
        .limit(this.refreshTokenCleanupBatchSize)
        .get();

      if (snapshot.empty) {
        break;
      }

      const batch = firestore.batch();
      snapshot.docs.forEach((doc) => batch.delete(doc.ref));
      await batch.commit();
      deletedTotal += snapshot.size;

      if (snapshot.size < this.refreshTokenCleanupBatchSize) {
        break;
      }
    }

    if (deletedTotal > 0) {
      this.logger.log(
        'cleanupExpiredRefreshTokens: deleted expired refresh tokens' +
          formatLogContext({
            deleted: deletedTotal,
          }),
      );
    }
  }

  async loginWithGoogle(googleUser: { email: string; name: string; googleId: string }) {
    this.logger.log(
      'loginWithGoogle start' +
        formatLogContext({
          email: maskEmail(googleUser.email),
          googleId: maskId(googleUser.googleId),
        }),
    );

    if (!googleUser.email) {
      this.logger.warn('loginWithGoogle: missing email from Google profile');
      throw new BadRequestException('Google account has no email');
    }

    const firestore = this.firestore;
    this.logger.log('loginWithGoogle: got firestore instance');

    const now = new Date();
    let userId: string | null = null;
    let loginStreak = 0;
    let longestLoginStreak = 0;

    const googleIdQuery = await firestore
      .collection('users')
      .where('googleId', '==', googleUser.googleId)
      .get();

    if (!googleIdQuery.empty) {
      const userDoc = googleIdQuery.docs[0];
      const user = userDoc.data() as any;
      userId = userDoc.id;
      await this.options.userCollectionsManager.ensureUserCollections(userDoc);

      const streakData = this.updateLoginStreak(user, now);

      await userDoc.ref.update({
        ...streakData,
      });

      loginStreak = streakData.loginStreak;
      longestLoginStreak = streakData.longestLoginStreak;

      this.logger.log(
        'loginWithGoogle: matched by googleId' +
          formatLogContext({
            googleId: maskId(googleUser.googleId),
            userId: maskId(userId),
          }),
      );
    } else {
      const emailQuery = await firestore
        .collection('users')
        .where('email', '==', googleUser.email)
        .get();

      if (!emailQuery.empty) {
        const userDoc = emailQuery.docs[0];
        const user = userDoc.data() as any;
        userId = userDoc.id;
        await this.options.userCollectionsManager.ensureUserCollections(userDoc);

        const streakData = this.updateLoginStreak(user, now);

        await userDoc.ref.update({
          googleId: googleUser.googleId,
          ...streakData,
        });

        loginStreak = streakData.loginStreak;
        longestLoginStreak = streakData.longestLoginStreak;

        this.logger.log(
          'loginWithGoogle: matched by email' +
            formatLogContext({
              email: maskEmail(googleUser.email),
              userId: maskId(userId),
            }),
        );
      } else {
        const streakData = this.updateLoginStreak(
          { lastLoginDate: null, loginStreak: 0, longestLoginStreak: 0 },
          now,
        );

        this.logger.log(
          'loginWithGoogle: creating new user' +
            formatLogContext({
              email: maskEmail(googleUser.email),
            }),
        );

        const newUserRef = await firestore.collection('users').add({
          email: googleUser.email,
          name: googleUser.name || googleUser.email,
          googleId: googleUser.googleId,
          emailVerified: true,
          password: null,
          createdAt: admin.firestore.Timestamp.fromDate(now),
          aboutMe: '',
          lessonPerformanceMatrix: [],
          testPerformanceMatrix: [],
          dictionaryEntries: [],
          favoriteGestures: [],
          avatarPath: null,
          avatarMimeType: null,
          avatarUpdatedAt: null,
          ...streakData,
        });

        userId = newUserRef.id;
        loginStreak = streakData.loginStreak;
        longestLoginStreak = streakData.longestLoginStreak;

        this.logger.log(
          'loginWithGoogle: new user created' +
            formatLogContext({
              userId: maskId(userId),
            }),
        );
      }
    }

    if (!userId) {
      this.logger.error('loginWithGoogle: failed to resolve userId');
      throw new UnauthorizedException();
    }

    const tokens = await this.generateUserToken(userId);
    this.logger.log('loginWithGoogle: tokens generated');
    return {
      ...tokens,
      loginStreak,
      longestLoginStreak,
    };
  }

  async loginWithApple(appleUser: { email: string; name: string; appleId: string }) {
    this.logger.log(
      'loginWithApple start' +
        formatLogContext({
          email: maskEmail(appleUser.email),
          appleId: maskId(appleUser.appleId),
        }),
    );

    if (!appleUser.appleId) {
      this.logger.warn('loginWithApple: missing appleId from Apple profile');
      throw new BadRequestException('Apple login has no appleId');
    }

    const firestore = this.firestore;
    this.logger.log('loginWithApple: got firestore instance');

    const now = new Date();
    let userId: string | null = null;
    let loginStreak = 0;
    let longestLoginStreak = 0;

    const appleIdQuery = await firestore
      .collection('users')
      .where('appleId', '==', appleUser.appleId)
      .get();

    if (!appleIdQuery.empty) {
      const userDoc = appleIdQuery.docs[0];
      const user = userDoc.data() as any;
      userId = userDoc.id;
      await this.options.userCollectionsManager.ensureUserCollections(userDoc);

      const streakData = this.updateLoginStreak(user, now);

      await userDoc.ref.update({
        ...streakData,
      });

      loginStreak = streakData.loginStreak;
      longestLoginStreak = streakData.longestLoginStreak;

      this.logger.log(
        'loginWithApple: matched by appleId' +
          formatLogContext({
            appleId: maskId(appleUser.appleId),
            userId: maskId(userId),
          }),
      );
    } else {
      if (!appleUser.email) {
        this.logger.warn(
          'loginWithApple: Apple did not provide email and no existing user found by appleId',
        );
        throw new BadRequestException(
          'Apple did not provide email. Please re-authorize email scope and try again.',
        );
      }

      const emailQuery = await firestore
        .collection('users')
        .where('email', '==', appleUser.email)
        .get();

      if (!emailQuery.empty) {
        const userDoc = emailQuery.docs[0];
        const user = userDoc.data() as any;
        userId = userDoc.id;
        await this.options.userCollectionsManager.ensureUserCollections(userDoc);

        const streakData = this.updateLoginStreak(user, now);

        await userDoc.ref.update({
          appleId: appleUser.appleId,
          ...streakData,
        });

        loginStreak = streakData.loginStreak;
        longestLoginStreak = streakData.longestLoginStreak;

        this.logger.log(
          'loginWithApple: matched by email' +
            formatLogContext({
              email: maskEmail(appleUser.email),
              userId: maskId(userId),
            }),
        );
      } else {
        const streakData = this.updateLoginStreak(
          { lastLoginDate: null, loginStreak: 0, longestLoginStreak: 0 },
          now,
        );

        this.logger.log(
          'loginWithApple: creating new user' +
            formatLogContext({
              email: maskEmail(appleUser.email),
            }),
        );

        const newUserRef = await firestore.collection('users').add({
          email: appleUser.email,
          name: appleUser.name || appleUser.email,
          appleId: appleUser.appleId,
          emailVerified: true,
          password: null,
          createdAt: admin.firestore.Timestamp.fromDate(now),
          aboutMe: '',
          lessonPerformanceMatrix: [],
          testPerformanceMatrix: [],
          dictionaryEntries: [],
          favoriteGestures: [],
          avatarPath: null,
          avatarMimeType: null,
          avatarUpdatedAt: null,
          ...streakData,
        });

        userId = newUserRef.id;
        loginStreak = streakData.loginStreak;
        longestLoginStreak = streakData.longestLoginStreak;

        this.logger.log(
          'loginWithApple: new user created' +
            formatLogContext({
              userId: maskId(userId),
            }),
        );
      }
    }

    if (!userId) {
      this.logger.error('loginWithApple: failed to resolve userId');
      throw new UnauthorizedException();
    }

    const tokens = await this.generateUserToken(userId);
    this.logger.log('loginWithApple: tokens generated');
    return {
      ...tokens,
      loginStreak,
      longestLoginStreak,
    };
  }
}
