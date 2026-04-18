import { Injectable, Inject, Logger, BadRequestException } from '@nestjs/common';
import { SignupDto } from './dto/signup.dto';
import * as admin from 'firebase-admin';
import 'firebase-admin/storage';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { MailerService } from './mailer.service';
import words from './words.json';
import { UpdateProfileDto } from './update-profile.dto';
import { ImageModerationService } from './image-moderation.service';
import { formatLogContext, maskEmail, maskId } from '../common/logging/redaction';
import { AvatarManager } from './managers/avatar.manager';
import type { AvatarUploadFile } from './managers/avatar.manager';
import { FriendshipManager } from './managers/friendship.manager';
import { UserCollectionsManager } from './managers/user-collections.manager';
import { AccountManager } from './managers/account.manager';
import { SessionManager } from './managers/session.manager';

export type { AvatarUploadFile } from './managers/avatar.manager';
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly lessonIds: number[] = this.buildIndexList(
    process.env.LESSON_IDS,
    Number(process.env.LESSON_COUNT ?? process.env.DEFAULT_LESSON_COUNT ?? '100'),
  );
  private readonly testIds: number[] = this.buildIndexList(
    process.env.TEST_IDS,
    Number(process.env.TEST_COUNT ?? process.env.DEFAULT_TEST_COUNT ?? '100'),
  );
  private readonly lessonIdSet = new Set(this.lessonIds);
  private readonly testIdSet = new Set(this.testIds);
  private readonly maxAvatarBytes = Number(process.env.AVATAR_MAX_BYTES ?? 5 * 1024 * 1024);
  private readonly avatarFolder = process.env.AVATAR_FOLDER || 'avatars';
  private readonly allowedAvatarMimeTypes = new Set(['image/png', 'image/jpeg', 'image/webp']);
  private readonly avatarSignedUrlExpiresInMs = Number(
    process.env.AVATAR_SIGNED_URL_TTL_MS ?? 5 * 60 * 1000,
  );
  private readonly avatarJpegQuality = this.clampPercentage(
    Number(process.env.AVATAR_JPEG_QUALITY ?? 80),
  );
  private readonly avatarWebpQuality = this.clampPercentage(
    Number(process.env.AVATAR_WEBP_QUALITY ?? 80),
  );
  private readonly avatarPngCompressionLevel = this.clampCompressionLevel(
    Number(process.env.AVATAR_PNG_COMPRESSION_LEVEL ?? 9),
  );
  private readonly friendshipsCollection = 'friendships';
  private readonly friendRequestsCollection = 'friendRequests';
  private readonly verificationCleanupBatchSize = Number(
    process.env.EMAIL_VERIFICATION_CLEANUP_BATCH_SIZE ?? 200,
  );
  private readonly refreshTokenCleanupBatchSize = Number(
    process.env.REFRESH_TOKEN_CLEANUP_BATCH_SIZE ?? 500,
  );
  private readonly userCollectionsManager: UserCollectionsManager;
  private readonly avatarManager: AvatarManager;
  private readonly friendshipManager: FriendshipManager;
  private readonly accountManager: AccountManager;
  private readonly sessionManager: SessionManager;

  // words.json ist ein reines Array von Strings
  private readonly forbiddenWords: string[] = (words as string[])
    .filter((w) => !!w)
    .map((w) => w.toLowerCase().trim());

  constructor(
    @Inject('FIREBASE_APP') private firebaseApp: admin.app.App,
    private jwtService: JwtService,
    private mailerService: MailerService,
    private readonly imageModerationService: ImageModerationService,
  ) {
    this.userCollectionsManager = new UserCollectionsManager({
      firebaseApp: this.firebaseApp,
      logger: this.logger,
      lessonIdSet: this.lessonIdSet,
      testIdSet: this.testIdSet,
    });

    this.avatarManager = new AvatarManager({
      firebaseApp: this.firebaseApp,
      logger: this.logger,
      avatarFolder: this.avatarFolder,
      maxAvatarBytes: this.maxAvatarBytes,
      allowedAvatarMimeTypes: this.allowedAvatarMimeTypes,
      avatarSignedUrlExpiresInMs: this.avatarSignedUrlExpiresInMs,
      avatarJpegQuality: this.avatarJpegQuality,
      avatarWebpQuality: this.avatarWebpQuality,
      avatarPngCompressionLevel: this.avatarPngCompressionLevel,
      imageModerationService: this.imageModerationService,
      userCollectionsManager: this.userCollectionsManager,
    });

    this.friendshipManager = new FriendshipManager({
      firebaseApp: this.firebaseApp,
      friendshipsCollection: this.friendshipsCollection,
      friendRequestsCollection: this.friendRequestsCollection,
      avatarManager: this.avatarManager,
    });

    this.accountManager = new AccountManager({
      firebaseApp: this.firebaseApp,
      logger: this.logger,
      mailerService: this.mailerService,
      verificationCleanupBatchSize: this.verificationCleanupBatchSize,
      forbiddenWords: this.forbiddenWords,
    });

    this.sessionManager = new SessionManager({
      firebaseApp: this.firebaseApp,
      logger: this.logger,
      jwtService: this.jwtService,
      userCollectionsManager: this.userCollectionsManager,
      refreshTokenCleanupBatchSize: this.refreshTokenCleanupBatchSize,
    });
  }

  // further logic delegated to specialized managers

  private buildIndexList(idsCsv?: string, count?: number): number[] {
    const parsedFromCsv =
      idsCsv
        ?.split(',')
        .map((part) => Number(part.trim()))
        .filter((n) => Number.isFinite(n) && n >= 0) ?? [];

    if (parsedFromCsv.length > 0) {
      return Array.from(new Set(parsedFromCsv)).sort((a, b) => a - b);
    }

    if (typeof count === 'number' && Number.isFinite(count) && count > 0) {
      return Array.from({ length: Math.floor(count) }, (_, index) => index);
    }

    return [];
  }

  private clampPercentage(value: number): number {
    if (!Number.isFinite(value)) {
      return 0;
    }
    return Math.max(0, Math.min(100, value));
  }

  private clampCompressionLevel(value: number): number {
    if (!Number.isFinite(value)) {
      return 9;
    }
    return Math.max(0, Math.min(9, Math.round(value)));
  }

  private getFirestore() {
    return this.firebaseApp.firestore();
  }

  async getLessonPerformance(userId: string) {
    return this.userCollectionsManager.getLessonPerformance(userId);
  }

  async updateLessonPerformance(userId: string, lessonId: number, percentage: number) {
    return this.userCollectionsManager.updateLessonPerformance(userId, lessonId, percentage);
  }

  async getTestPerformance(userId: string) {
    return this.userCollectionsManager.getTestPerformance(userId);
  }

  async updateTestPerformance(userId: string, testId: number, percentage: number) {
    return this.userCollectionsManager.updateTestPerformance(userId, testId, percentage);
  }

  async setLessonPerformanceMatrix(
    userId: string,
    entries: { lessonId: number; percentage: number }[],
  ) {
    const payload = entries.map((entry) => ({
      id: entry.lessonId,
      percentage: entry.percentage,
    }));
    return this.userCollectionsManager.setLessonPerformanceMatrix(userId, payload);
  }

  async setTestPerformanceMatrix(
    userId: string,
    entries: { testId: number; percentage: number }[],
  ) {
    const payload = entries.map((entry) => ({
      id: entry.testId,
      percentage: entry.percentage,
    }));
    return this.userCollectionsManager.setTestPerformanceMatrix(userId, payload);
  }

  async getDictionaryEntries(userId: string) {
    return this.userCollectionsManager.getDictionaryEntries(userId);
  }

  async updateDictionaryEntries(userId: string, entries: string[]) {
    return this.userCollectionsManager.updateDictionaryEntries(userId, entries);
  }

  async getFavoriteGestures(userId: string) {
    return this.userCollectionsManager.getFavoriteGestures(userId);
  }

  async updateFavoriteGestures(userId: string, entries: string[]) {
    return this.userCollectionsManager.updateFavoriteGestures(userId, entries);
  }

  async getBadges(userId: string) {
    return this.userCollectionsManager.getBadges(userId);
  }

  async updateBadges(userId: string, badges: number[][]) {
    return this.userCollectionsManager.updateBadges(userId, badges);
  }

  async getAvatar(userId: string) {
    return this.avatarManager.getAvatar(userId);
  }

  async downloadAvatar(userId: string) {
    return this.avatarManager.downloadAvatar(userId);
  }

  async uploadAvatar(userId: string, file?: AvatarUploadFile) {
    return this.avatarManager.uploadAvatar(userId, file);
  }

  async deleteAvatar(userId: string) {
    return this.avatarManager.deleteAvatar(userId);
  }

  async sendFriendRequest(fromUserId: string, targetUsername: string) {
    return this.friendshipManager.sendFriendRequest(fromUserId, targetUsername);
  }

  async getIncomingFriendRequests(userId: string) {
    return this.friendshipManager.getIncomingFriendRequests(userId);
  }

  async respondToFriendRequest(userId: string, requestId: string, accept: boolean) {
    return this.friendshipManager.respondToFriendRequest(userId, requestId, accept);
  }

  async getFriends(userId: string) {
    return this.friendshipManager.getFriends(userId);
  }

  async getProfileAbout(userId: string) {
    return this.userCollectionsManager.getProfileAbout(userId);
  }

  async signup(signupData: SignupDto) {
    return this.accountManager.signup(signupData);
  }

  async login(credentials: LoginDto) {
    return this.sessionManager.login(credentials);
  }

  async refreshTokens(refreshToken: string) {
    return this.sessionManager.refreshTokens(refreshToken);
  }

  async generateUserToken(userId: string) {
    return this.sessionManager.generateUserToken(userId);
  }

  async storeRefreshToken(token: string, userId: string) {
    return this.sessionManager.storeRefreshToken(token, userId);
  }

  async verifyEmailToken(token: string): Promise<{
    success: boolean;
    error?: string;
    message: string;
    userId?: string;
    email?: string;
    name?: string;
  }> {
    return this.accountManager.verifyEmailToken(token);
  }

  // Google-Login mit Login-Streak
  async loginWithGoogle(googleUser: { email: string; name: string; googleId: string }) {
    return this.sessionManager.loginWithGoogle(googleUser);
  }

  // Apple-Login mit Login-Streak
  async loginWithApple(appleUser: { email: string; name: string; appleId: string }) {
    return this.sessionManager.loginWithApple(appleUser);
  }

  // Profil aktualisieren (Name + AboutMe)
  async updateProfile(userId: string, dto: UpdateProfileDto) {
    return this.accountManager.updateProfile(userId, dto);
  }

  async deleteAccount(userId: string) {
    this.logger.log(
      'deleteAccount start' +
        formatLogContext({
          userId: maskId(userId),
        }),
    );

    const firestore = this.getFirestore();
    const userRef = firestore.collection('users').doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      this.logger.warn(
        'deleteAccount: user not found' +
          formatLogContext({
            userId: maskId(userId),
          }),
      );
      throw new BadRequestException('User not found');
    }

    const userData = userDoc.data() as any;
    const email = typeof userData?.email === 'string' ? userData.email : undefined;
    const avatarPath = typeof userData?.avatarPath === 'string' ? userData.avatarPath : undefined;

    if (avatarPath) {
      try {
        await this.firebaseApp.storage().bucket().file(avatarPath).delete({ ignoreNotFound: true });
      } catch (err: any) {
        this.logger.warn(
          'deleteAccount: failed to delete avatar from storage' +
            formatLogContext({
              userId: maskId(userId),
              avatarPath,
              error: err?.message,
            }),
        );
      }
    }

    const batchSize = 400;
    const deletedRefreshTokens = await this.deleteQueryInBatches(
      firestore.collection('refreshTokens').where('userId', '==', userId),
      batchSize,
    );

    const deletedPasswordResets = await this.deleteQueryInBatches(
      firestore.collection('passwordResets').where('userId', '==', userId),
      batchSize,
    );

    const deletedFriendRequestsOutgoing = await this.deleteQueryInBatches(
      firestore
        .collection(this.friendRequestsCollection)
        .where('fromUserId', '==', userId),
      batchSize,
    );

    const deletedFriendRequestsIncoming = await this.deleteQueryInBatches(
      firestore
        .collection(this.friendRequestsCollection)
        .where('toUserId', '==', userId),
      batchSize,
    );

    const deletedFriendshipsA = await this.deleteQueryInBatches(
      firestore.collection(this.friendshipsCollection).where('userA', '==', userId),
      batchSize,
    );

    const deletedFriendshipsB = await this.deleteQueryInBatches(
      firestore.collection(this.friendshipsCollection).where('userB', '==', userId),
      batchSize,
    );

    const deletedEmailVerifications = email
      ? await this.deleteQueryInBatches(
          firestore.collection('emailVerifications').where('email', '==', email),
          batchSize,
        )
      : 0;

    await userRef.delete();

    this.logger.log(
      'deleteAccount finished' +
        formatLogContext({
          userId: maskId(userId),
          email: maskEmail(email),
          refreshTokensDeleted: deletedRefreshTokens,
          passwordResetsDeleted: deletedPasswordResets,
          friendRequestsDeleted: deletedFriendRequestsOutgoing + deletedFriendRequestsIncoming,
          friendshipsDeleted: deletedFriendshipsA + deletedFriendshipsB,
          emailVerificationsDeleted: deletedEmailVerifications,
        }),
    );

    return { success: true, message: 'Account geloescht' };
  }

  private async deleteQueryInBatches(
    query: admin.firestore.Query,
    batchSize: number,
  ): Promise<number> {
    let deleted = 0;
    const firestore = this.getFirestore();

    while (true) {
      const snapshot = await query.limit(batchSize).get();
      if (snapshot.empty) {
        break;
      }

      const batch = firestore.batch();
      snapshot.docs.forEach((doc) => batch.delete(doc.ref));
      await batch.commit();
      deleted += snapshot.size;

      if (snapshot.size < batchSize) {
        break;
      }
    }

    return deleted;
  }

  /**
   * Returns the current login streak information for a given userId.
   * Used by the frontend to display the user's current streak without
   * modifying it.
   */
  async getStreak(userId: string) {
    this.logger.log(
      'getStreak start' +
        formatLogContext({
          userId: maskId(userId),
        }),
    );

    try {
      await this.sessionManager.ensureLoginStreakIsCurrent(userId);
    } catch (err: any) {
      this.logger.error(
        'getStreak: failed to ensure login streak is current' +
          formatLogContext({
            userId: maskId(userId),
            error: err?.message,
          }),
        err?.stack,
      );
    }

    return this.userCollectionsManager.getStreak(userId);
  }
}
