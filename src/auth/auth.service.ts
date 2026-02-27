import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
  Inject,
  Logger,
} from '@nestjs/common';
import { SignupDto } from './dto/signup.dto';
import * as admin from 'firebase-admin';
import 'firebase-admin/storage';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { MailerService } from './mailer.service';
import words from './words.json';
import { UpdateProfileDto } from './update-profile.dto';
export type AvatarUploadFile = {
  buffer: Buffer;
  mimetype: string;
  size: number;
};

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

  // words.json ist ein reines Array von Strings
  private readonly forbiddenWords: string[] = (words as string[])
    .filter((w) => !!w)
    .map((w) => w.toLowerCase().trim());

  constructor(
    @Inject('FIREBASE_APP') private firebaseApp: admin.app.App,
    private jwtService: JwtService,
    private mailerService: MailerService,
  ) {}

  private validateNameAgainstForbiddenWords(name: string): void {
    const nameLower = (name || '').toLowerCase();

    const hit = this.forbiddenWords.find((word) => {
      const w = word.toLowerCase();
      if (!w) return false;
      return nameLower.includes(w);
    });

    if (hit) {
      this.logger.warn(`signup: forbidden name "${name}" contains "${hit}"`);
      throw new BadRequestException('Dieser Benutzername ist nicht erlaubt');
    }
  }

  /**
   * Login-Streak aktualisieren.
   * Nutzt lastLoginDate (YYYY-MM-DD) + loginStreak + longestLoginStreak im User-Dokument.
   */
  private updateLoginStreak(
    user: any,
    now: Date,
  ): { loginStreak: number; longestLoginStreak: number; lastLoginDate: string } {
    const currentDate = now.toISOString().slice(0, 10); // YYYY-MM-DD

    const last = user.lastLoginDate as string | undefined;
    let loginStreak = user.loginStreak as number | undefined;
    let longestLoginStreak = user.longestLoginStreak as number | undefined;

    if (!last) {
      // erster Login
      loginStreak = 1;
    } else {
      const lastDate = new Date(last);
      const diffDays = Math.floor(
        (Date.UTC(now.getFullYear(), now.getMonth(), now.getDate()) -
          Date.UTC(lastDate.getFullYear(), lastDate.getMonth(), lastDate.getDate())) /
          (1000 * 60 * 60 * 24),
      );

      if (diffDays === 0) {
        // heute schon eingeloggt → Streak bleibt
        loginStreak = loginStreak || 1;
      } else if (diffDays === 1) {
        // gestern → Streak +1
        loginStreak = (loginStreak || 0) + 1;
      } else {
        // Lücke → reset
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

  private getMatrixKey(kind: 'lesson' | 'test'): 'lessonPerformanceMatrix' | 'testPerformanceMatrix' {
    return kind === 'lesson' ? 'lessonPerformanceMatrix' : 'testPerformanceMatrix';
  }

  private getAllowedIdSet(kind: 'lesson' | 'test'): Set<number> | undefined {
    const source = kind === 'lesson' ? this.lessonIdSet : this.testIdSet;
    return source.size > 0 ? source : undefined;
  }

  private normalizePerformanceMatrixInput(
    value: any,
    kind: 'lesson' | 'test',
    strict = false,
  ): number[][] {
    const allowedSet = this.getAllowedIdSet(kind);

    if (!Array.isArray(value)) {
      if (strict && value !== undefined) {
        throw new BadRequestException(
          kind === 'lesson'
            ? 'lessonPerformanceMatrix muss ein Array sein'
            : 'testPerformanceMatrix muss ein Array sein',
        );
      }
      return [];
    }

    const sanitized = new Map<number, number>();

    for (const rawEntry of value) {
      if (rawEntry == null) {
        if (strict) {
          throw new BadRequestException('Performance-Einträge dürfen nicht leer sein');
        }
        continue;
      }

      let idValue: any;
      let percentageValue: any;

      if (Array.isArray(rawEntry) && rawEntry.length >= 2) {
        [idValue, percentageValue] = rawEntry;
      } else if (typeof rawEntry === 'object') {
        idValue =
          (rawEntry as any).lessonId ??
          (rawEntry as any).testId ??
          (rawEntry as any).id ??
          (rawEntry as any).index;
        percentageValue =
          (rawEntry as any).percentage ?? (rawEntry as any).value ?? (rawEntry as any).progress;
      } else {
        if (strict) {
          throw new BadRequestException(
            kind === 'lesson'
              ? 'lessonPerformanceMatrix erwartet lessonId & percentage'
              : 'testPerformanceMatrix erwartet testId & percentage',
          );
        }
        continue;
      }

      const numericId = Number(idValue);
      const numericPercentage = Number(percentageValue);

      if (!Number.isFinite(numericId) || !Number.isFinite(numericPercentage)) {
        if (strict) {
          throw new BadRequestException(
            kind === 'lesson'
              ? 'lessonPerformanceMatrix benötigt numerische lessonId & percentage'
              : 'testPerformanceMatrix benötigt numerische testId & percentage',
          );
        }
        continue;
      }

      const normalizedId = Math.floor(numericId);
      if (allowedSet && !allowedSet.has(normalizedId)) {
        const message = kind === 'lesson' ? 'Unknown lessonId' : 'Unknown testId';
        if (strict) {
          throw new BadRequestException(message);
        }
        continue;
      }

      sanitized.set(normalizedId, this.clampPercentage(numericPercentage));
    }

    return Array.from(sanitized.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([id, percentage]) => [id, percentage]);
  }

  private arraysEqual(a: any, b: any): boolean {
    return JSON.stringify(a ?? []) === JSON.stringify(b ?? []);
  }

  private normalizeStringArray(value: any): string[] {
    if (!Array.isArray(value)) {
      return [];
    }
    const seen = new Set<string>();
    const normalized: string[] = [];
    for (const entry of value) {
      if (typeof entry !== 'string') {
        continue;
      }
      const trimmed = entry.trim();
      if (!trimmed || seen.has(trimmed)) {
        continue;
      }
      normalized.push(trimmed);
      seen.add(trimmed);
    }
    return normalized;
  }

  private sanitizeStringArrayInput(value: any, fieldName: string): string[] {
    if (!Array.isArray(value)) {
      throw new BadRequestException(`${fieldName} muss ein Array aus Strings sein`);
    }
    const invalid = value.some((entry) => typeof entry !== 'string');
    if (invalid) {
      throw new BadRequestException(`${fieldName} darf nur Strings enthalten`);
    }
    return this.normalizeStringArray(value);
  }

  private getStorageBucket() {
    return this.firebaseApp.storage().bucket();
  }

  private detectAvatarExtension(mimeType: string) {
    if (mimeType === 'image/png') return 'png';
    if (mimeType === 'image/webp') return 'webp';
    return 'jpg';
  }

  private validateAvatarMagicBytes(buffer: Buffer, mimeType: string) {
    if (mimeType === 'image/png') {
      return buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47;
    }

    if (mimeType === 'image/jpeg') {
      return buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[buffer.length - 2] === 0xff && buffer[buffer.length - 1] === 0xd9;
    }

    if (mimeType === 'image/webp') {
      return (
        buffer[0] === 0x52 && // R
        buffer[1] === 0x49 && // I
        buffer[2] === 0x46 && // F
        buffer[3] === 0x46 && // F
        buffer[8] === 0x57 && // W
        buffer[9] === 0x45 && // E
        buffer[10] === 0x42 && // B
        buffer[11] === 0x50
      );
    }

    return false;
  }

  private sanitizeAvatarFile(file?: AvatarUploadFile) {
    if (!file) {
      throw new BadRequestException('avatar-Datei fehlt');
    }

    if (!file.buffer || !file.buffer.length) {
      throw new BadRequestException('avatar-Datei konnte nicht gelesen werden');
    }

    if (file.buffer.length > this.maxAvatarBytes) {
      throw new BadRequestException(
        `Avatar ist zu groß (max ${(this.maxAvatarBytes / (1024 * 1024)).toFixed(1)}MB)`,
      );
    }

    const mimeType = (file.mimetype || '').toLowerCase();
    if (!this.allowedAvatarMimeTypes.has(mimeType)) {
      throw new BadRequestException('Unterstützte Avatar-Typen: PNG, JPEG, WEBP');
    }

    if (file.buffer.length < 4) {
      throw new BadRequestException('Ungültiges Bildformat');
    }

    if (!this.validateAvatarMagicBytes(file.buffer, mimeType)) {
      throw new BadRequestException('Ungültiges Bildformat');
    }

    return { buffer: file.buffer, mimeType };
  }

  private async ensureUserCollections(
    userDoc: admin.firestore.QueryDocumentSnapshot | admin.firestore.DocumentSnapshot,
  ): Promise<void> {
    const data = userDoc.data();
    if (!data) return;

    const updates: Record<string, any> = {};

    const normalizedLesson = this.normalizePerformanceMatrixInput(
      data.lessonPerformanceMatrix,
      'lesson',
    );
    if (!this.arraysEqual(data.lessonPerformanceMatrix, normalizedLesson)) {
      updates.lessonPerformanceMatrix = normalizedLesson;
    }

    const normalizedTest = this.normalizePerformanceMatrixInput(data.testPerformanceMatrix, 'test');
    if (!this.arraysEqual(data.testPerformanceMatrix, normalizedTest)) {
      updates.testPerformanceMatrix = normalizedTest;
    }

    const normalizedDictionary = this.normalizeStringArray(data.dictionaryEntries);
    if (!this.arraysEqual(data.dictionaryEntries, normalizedDictionary)) {
      updates.dictionaryEntries = normalizedDictionary;
    }

    const normalizedFavorites = this.normalizeStringArray(data.favoriteGestures);
    if (!this.arraysEqual(data.favoriteGestures, normalizedFavorites)) {
      updates.favoriteGestures = normalizedFavorites;
    }

    if (Object.keys(updates).length > 0) {
      await userDoc.ref.update(updates);
      this.logger.log(
        `ensureUserCollections: normalized arrays for user=${userDoc.id}`,
      );
    }
  }

  private async getUserDocument(userId: string) {
    const firestore = this.firebaseApp.firestore();
    const userRef = firestore.collection('users').doc(userId);
    const userDoc = await userRef.get();
    if (!userDoc.exists) {
      this.logger.warn(`getUserDocument: user not found userId=${userId}`);
      throw new BadRequestException('User not found');
    }
    await this.ensureUserCollections(userDoc);
    return { userDoc, userRef };
  }

  private async updatePerformanceMatrix(
    userId: string,
    matrixKey: 'lessonPerformanceMatrix' | 'testPerformanceMatrix',
    entryId: number,
    percentage: number,
  ): Promise<number[][]> {
    const kind: 'lesson' | 'test' =
      matrixKey === 'lessonPerformanceMatrix' ? 'lesson' : 'test';
    const allowedSet = this.getAllowedIdSet(kind);
    const normalizedEntryId = Math.floor(Number(entryId));

    if (!Number.isFinite(normalizedEntryId)) {
      this.logger.warn(
        `updatePerformanceMatrix: invalid ${kind} id: ${entryId} for userId=${userId}`,
      );
      throw new BadRequestException(
        kind === 'lesson' ? 'lessonId ist ungültig' : 'testId ist ungültig',
      );
    }

    if (allowedSet && !allowedSet.has(normalizedEntryId)) {
      this.logger.warn(
        `updatePerformanceMatrix: entryId ${normalizedEntryId} not allowed for ${matrixKey}`,
      );
      throw new BadRequestException(
        matrixKey === 'lessonPerformanceMatrix'
          ? 'Unknown lessonId'
          : 'Unknown testId',
      );
    }

    const firestore = this.firebaseApp.firestore();
    const clampedPercentage = this.clampPercentage(percentage);
    const userRef = firestore.collection('users').doc(userId);

    const updatedMatrix = await firestore.runTransaction(async (tx) => {
      const userSnap = await tx.get(userRef);
      if (!userSnap.exists) {
        this.logger.warn(`updatePerformanceMatrix: user not found userId=${userId}`);
        throw new BadRequestException('User not found');
      }

      const data = userSnap.data() || {};
      const matrix = this.normalizePerformanceMatrixInput(data[matrixKey], kind);
      const next = this.mergePerformanceEntry(matrix, normalizedEntryId, clampedPercentage);

      tx.update(userRef, {
        [matrixKey]: next,
      });

      return next;
    });

    this.logger.log(
      `updatePerformanceMatrix: updated ${matrixKey} for userId=${userId}, entryId=${normalizedEntryId}, percentage=${clampedPercentage}`,
    );

    return updatedMatrix;
  }

  private mergePerformanceEntry(matrix: number[][], entryId: number, percentage: number) {
    const next = matrix.map(([id, value]) => [id, value]);
    const existingIndex = next.findIndex(([id]) => id === entryId);

    if (existingIndex >= 0) {
      next[existingIndex][1] = percentage;
    } else {
      next.push([entryId, percentage]);
    }

    next.sort((a, b) => a[0] - b[0]);
    return next;
  }

  private async replacePerformanceMatrix(
    userId: string,
    kind: 'lesson' | 'test',
    entries: { id: number; percentage: number }[],
  ): Promise<number[][]> {
    const matrixKey = this.getMatrixKey(kind);
    const payload = entries.map((entry) => [entry.id, entry.percentage]);
    const normalized = this.normalizePerformanceMatrixInput(payload, kind, true);
    const { userRef } = await this.getUserDocument(userId);

    await userRef.update({
      [matrixKey]: normalized,
    });

    this.logger.log(
      `replacePerformanceMatrix: replaced ${matrixKey} for userId=${userId} with ${normalized.length} entries`,
    );

    return normalized;
  }

  async getLessonPerformance(userId: string) {
    const { userDoc } = await this.getUserDocument(userId);
    const data = userDoc.data() as any;
    return {
      lessonPerformanceMatrix: this.normalizePerformanceMatrixInput(
        data?.lessonPerformanceMatrix,
        'lesson',
      ),
    };
  }

  async updateLessonPerformance(userId: string, lessonId: number, percentage: number) {
    const lessonPerformanceMatrix = await this.updatePerformanceMatrix(
      userId,
      'lessonPerformanceMatrix',
      lessonId,
      percentage,
    );
    return { lessonPerformanceMatrix };
  }

  async getTestPerformance(userId: string) {
    const { userDoc } = await this.getUserDocument(userId);
    const data = userDoc.data() as any;
    return {
      testPerformanceMatrix: this.normalizePerformanceMatrixInput(
        data?.testPerformanceMatrix,
        'test',
      ),
    };
  }

  async updateTestPerformance(userId: string, testId: number, percentage: number) {
    const testPerformanceMatrix = await this.updatePerformanceMatrix(
      userId,
      'testPerformanceMatrix',
      testId,
      percentage,
    );
    return { testPerformanceMatrix };
  }

  async setLessonPerformanceMatrix(
    userId: string,
    entries: { lessonId: number; percentage: number }[],
  ) {
    const payload = entries.map((entry) => ({
      id: entry.lessonId,
      percentage: entry.percentage,
    }));
    const lessonPerformanceMatrix = await this.replacePerformanceMatrix(
      userId,
      'lesson',
      payload,
    );
    return { lessonPerformanceMatrix };
  }

  async setTestPerformanceMatrix(
    userId: string,
    entries: { testId: number; percentage: number }[],
  ) {
    const payload = entries.map((entry) => ({
      id: entry.testId,
      percentage: entry.percentage,
    }));
    const testPerformanceMatrix = await this.replacePerformanceMatrix(userId, 'test', payload);
    return { testPerformanceMatrix };
  }

  async getDictionaryEntries(userId: string) {
    const { userDoc } = await this.getUserDocument(userId);
    const data = userDoc.data() as any;
    return {
      dictionaryEntries: this.normalizeStringArray(data?.dictionaryEntries),
    };
  }

  async updateDictionaryEntries(userId: string, entries: string[]) {
    const sanitized = this.sanitizeStringArrayInput(entries, 'dictionaryEntries');
    const { userRef } = await this.getUserDocument(userId);
    await userRef.update({ dictionaryEntries: sanitized });
    this.logger.log(`updateDictionaryEntries: stored ${sanitized.length} entries for ${userId}`);
    return { dictionaryEntries: sanitized };
  }

  async getFavoriteGestures(userId: string) {
    const { userDoc } = await this.getUserDocument(userId);
    const data = userDoc.data() as any;
    return {
      favoriteGestures: this.normalizeStringArray(data?.favoriteGestures),
    };
  }

  async updateFavoriteGestures(userId: string, entries: string[]) {
    const sanitized = this.sanitizeStringArrayInput(entries, 'favoriteGestures');
    const { userRef } = await this.getUserDocument(userId);
    await userRef.update({ favoriteGestures: sanitized });
    this.logger.log(
      `updateFavoriteGestures: stored ${sanitized.length} favorite gestures for ${userId}`,
    );
    return { favoriteGestures: sanitized };
  }

  async getAvatar(userId: string) {
    const { userDoc } = await this.getUserDocument(userId);
    const data = userDoc.data() as any;
    const avatarPath = data?.avatarPath;
    if (!avatarPath) {
      return {
        avatarUrl: null,
        avatarMimeType: null,
        avatarUpdatedAt: data?.avatarUpdatedAt ?? null,
      };
    }

    const bucket = this.getStorageBucket();
    const fileRef = bucket.file(avatarPath);
    const expiresAt = Date.now() + this.avatarSignedUrlExpiresInMs;

    try {
      const [url] = await fileRef.getSignedUrl({
        action: 'read',
        expires: expiresAt,
      });

      return {
        avatarUrl: url,
        avatarMimeType: data?.avatarMimeType ?? null,
        avatarUpdatedAt: data?.avatarUpdatedAt ?? null,
        expiresAt,
      };
    } catch (err: any) {
      this.logger.warn(
        `getAvatar: failed to sign URL for ${avatarPath} (${userId}): ${err?.message}`,
      );
      return {
        avatarUrl: null,
        avatarMimeType: null,
        avatarUpdatedAt: data?.avatarUpdatedAt ?? null,
      };
    }
  }

  async uploadAvatar(userId: string, file?: AvatarUploadFile) {
    const { buffer, mimeType } = this.sanitizeAvatarFile(file);
    const { userDoc, userRef } = await this.getUserDocument(userId);
    const previousPath = (userDoc.data() as any)?.avatarPath;
    const extension = this.detectAvatarExtension(mimeType);
    const newPath = `${this.avatarFolder}/${userId}/${uuidv4()}.${extension}`;
    const bucket = this.getStorageBucket();
    const fileRef = bucket.file(newPath);

    await fileRef.save(buffer, {
      resumable: false,
      contentType: mimeType,
      metadata: { cacheControl: 'private, max-age=0' },
    });

    if (previousPath) {
      try {
        await bucket.file(previousPath).delete({ ignoreNotFound: true });
      } catch (err: any) {
        this.logger.warn(
          `uploadAvatar: failed to delete old avatar ${previousPath} for userId=${userId}: ${err?.message}`,
        );
      }
    }

    await userRef.update({
      avatarPath: newPath,
      avatarMimeType: mimeType,
      avatarUpdatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    this.logger.log(
      `uploadAvatar: stored avatar ${newPath} (${buffer.length} bytes) for userId=${userId}`,
    );

    return {
      avatarPath: newPath,
      avatarMimeType: mimeType,
    };
  }

  async deleteAvatar(userId: string) {
    const { userDoc, userRef } = await this.getUserDocument(userId);
    const data = userDoc.data() as any;
    const avatarPath = data?.avatarPath;

    if (avatarPath) {
      const bucket = this.getStorageBucket();
      try {
        await bucket.file(avatarPath).delete({ ignoreNotFound: true });
      } catch (err: any) {
        this.logger.warn(
          `deleteAvatar: failed to delete ${avatarPath} for userId=${userId}: ${err?.message}`,
        );
      }
    }

    await userRef.update({
      avatarPath: admin.firestore.FieldValue.delete(),
      avatarMimeType: admin.firestore.FieldValue.delete(),
      avatarUpdatedAt: admin.firestore.FieldValue.delete(),
    });

    this.logger.log(`deleteAvatar: removed avatar metadata for userId=${userId}`);
    return { success: true };
  }

  async signup(signupData: SignupDto) {
    this.logger.log(`signup start: ${JSON.stringify(signupData)}`);

    const rawNameFromDto =
      (signupData && (signupData as any).name) ||
      (signupData && (signupData as any).username) ||
      (signupData && (signupData as any).displayName) ||
      '';
    const name = (typeof rawNameFromDto === 'string' ? rawNameFromDto.trim() : '').trim();

    const { email, password } = signupData as any;

    if (!email || typeof email !== 'string' || !email.trim()) {
      this.logger.warn('signup: missing email');
      throw new BadRequestException('Email ist erforderlich');
    }
    if (!password || typeof password !== 'string' || !password.trim()) {
      this.logger.warn('signup: missing password');
      throw new BadRequestException('Passwort ist erforderlich');
    }
    if (!name) {
      this.logger.warn(`signup: missing name (raw: ${JSON.stringify(rawNameFromDto)})`);
      throw new BadRequestException('Name ist erforderlich');
    }

    // Name gegen Schimpfwörter prüfen
    this.validateNameAgainstForbiddenWords(name);

    try {
      const firestore = this.firebaseApp.firestore();
      this.logger.log('signup: got firestore instance');

      const emailRef = firestore.collection('users').where('email', '==', email);
      const emailSnapshot = await emailRef.get();
      this.logger.log(`signup: existing users with email=${email}: ${emailSnapshot.size}`);

      if (!emailSnapshot.empty) {
        this.logger.warn(`signup: email already in use: ${email}`);
        throw new BadRequestException('Diese Email hat bereits einen Account');
      }

      const nameRef = firestore.collection('users').where('name', '==', name);
      const nameSnapshot = await nameRef.get();
      this.logger.log(`signup: existing users with name=${name}: ${nameSnapshot.size}`);

      if (!nameSnapshot.empty) {
        this.logger.warn(`signup: name already in use: ${name}`);
        throw new BadRequestException('Dieser Benutzername ist bereits vergeben');
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      this.logger.log('signup: password hashed');

      const oldTokensQuery = await firestore
        .collection('emailVerifications')
        .where('email', '==', email)
        .get();

      if (!oldTokensQuery.empty) {
        this.logger.log(`signup: deleting ${oldTokensQuery.size} old tokens for ${email}`);
        const deletePromises = oldTokensQuery.docs.map((doc) => doc.ref.delete());
        await Promise.all(deletePromises);
      }

      const token = uuidv4();
      const createdAt = new Date();
      const expiresAt = new Date(createdAt.getTime() + 15 * 60 * 1000);

      this.logger.log(`signup: creating token ${token}`);
      this.logger.log(`signup: token expires at ${expiresAt.toISOString()}`);
      this.logger.log(`signup: server time: ${createdAt.toISOString()}`);

      await firestore.collection('emailVerifications').doc(token).set({
        email,
        password: hashedPassword,
        name,
        createdAt: admin.firestore.Timestamp.fromDate(createdAt),
        expiresAt: admin.firestore.Timestamp.fromDate(expiresAt),
      });

      this.logger.log('signup: email verification document created with token as document ID');

      await this.mailerService.sendVerificationEmail(email, token, name);
      this.logger.log('signup: verification email sent');

      return {
        success: true,
        message:
          'Verifizierungsmail gesendet. Bitte E-Mail innerhalb von 15 Minuten bestätigen.',
      };
    } catch (err) {
      this.logger.error(`signup internal error: ${err?.message}`, err?.stack);
      throw err;
    }
  }

  async login(credentials: LoginDto) {
    this.logger.log(`login start: ${JSON.stringify(credentials)}`);

    const { identifier, password } = credentials as any;

    try {
      const firestore = this.firebaseApp.firestore();
      this.logger.log('login: got firestore instance');

      const isEmail = typeof identifier === 'string' && identifier.includes('@');

      const userQuery = isEmail
        ? firestore.collection('users').where('email', '==', identifier)
        : firestore.collection('users').where('name', '==', identifier);

      const snapshot = await userQuery.get();
      this.logger.log(
        `login: users found with ${isEmail ? 'email' : 'name'}=${identifier}: ${snapshot.size}`,
      );

      if (snapshot.empty) {
        this.logger.warn(`login: no user found for ${isEmail ? 'email' : 'name'}=${identifier}`);
        throw new UnauthorizedException('Wrong credentials');
      }

      const userDoc = snapshot.docs[0];
      await this.ensureUserCollections(userDoc);
      const user = userDoc.data() as any;
      this.logger.log(`login: userDoc id=${userDoc.id}, user=${JSON.stringify(user)}`);

      const passwordMatch = await bcrypt.compare(password, user.password);
      this.logger.log(`login: passwordMatch=${passwordMatch}`);

      if (!passwordMatch) {
        this.logger.warn(`login: wrong password for ${isEmail ? 'email' : 'name'}=${identifier}`);
        throw new UnauthorizedException('Wrong credentials');
      }

      // Login-Streak aktualisieren
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
    this.logger.log(`refreshTokens start: token=${refreshToken}`);

    try {
      const firestore = this.firebaseApp.firestore();
      this.logger.log('refreshTokens: got firestore instance');

      const tokenRef = firestore
        .collection('refreshTokens')
        .where('token', '==', refreshToken)
        .where('expiryDate', '>=', new Date());

      const snapshot = await tokenRef.get();
      this.logger.log(`refreshTokens: tokens found=${snapshot.size}`);

      if (snapshot.empty) {
        this.logger.warn('refreshTokens: token not found or expired');
        throw new UnauthorizedException();
      }

      const tokenDoc = snapshot.docs[0];
      const token = tokenDoc.data() as any;
      this.logger.log(`refreshTokens: tokenDoc id=${tokenDoc.id}, userId=${token.userId}`);

      const tokens = await this.generateUserToken(token.userId);
      this.logger.log('refreshTokens: new tokens generated');
      return tokens;
    } catch (err) {
      this.logger.error(`refreshTokens internal error: ${err?.message}`, err?.stack);
      throw err;
    }
  }

  async generateUserToken(userId: string) {
    this.logger.log(`generateUserToken start: userId=${userId}`);

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
    this.logger.log(`storeRefreshToken start: userId=${userId}`);

    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);

    const firestore = this.firebaseApp.firestore();
    this.logger.log('storeRefreshToken: got firestore instance');

    await firestore.collection('refreshTokens').add({
      token,
      userId,
      expiryDate: admin.firestore.Timestamp.fromDate(expiryDate),
    });
    this.logger.log('storeRefreshToken: refresh token document created');
  }

  async verifyEmailToken(token: string): Promise<{
    success: boolean;
    error?: string;
    message: string;
    userId?: string;
    email?: string;
    name?: string;
  }> {
    this.logger.log(`verifyEmailToken START: token='${token}'`);

    const firestore = this.firebaseApp.firestore();

    try {
      const docRef = firestore.collection('emailVerifications').doc(token);
      const doc = await docRef.get();

      if (!doc.exists) {
        this.logger.error(`verifyEmailToken: document not found for token`);
        return {
          success: false,
          error: 'INVALID_TOKEN',
          message: 'Ungültiger oder abgelaufener Token',
          email: '',
        };
      }

      const tokenData = doc.data() as any;
      if (!tokenData) {
        this.logger.warn(`verifyEmailToken: document has no data`);
        return {
          success: false,
          error: 'INVALID_TOKEN_DATA',
          message: 'Ungültige Token-Daten',
          email: '',
        };
      }

      const email: string = (tokenData.email && String(tokenData.email)) || '';
      const password = tokenData.password;
      const name: string = (tokenData.name && String(tokenData.name)) || '';

      this.logger.log(`verifyEmailToken: tokenData.email='${email}', name='${name}'`);

      if (!email || !password) {
        this.logger.warn(`verifyEmailToken: missing required fields`);
        return {
          success: false,
          error: 'MISSING_FIELDS',
          message: 'Fehlende Benutzerdaten',
          email: email || '',
        };
      }

      const userQuery = await firestore.collection('users').where('email', '==', email).get();

      if (!userQuery.empty) {
        this.logger.log(`verifyEmailToken: user already exists for email: ${email}`);
        const existingUser = userQuery.docs[0];
        try {
          await docRef.delete();
          this.logger.log(
            `verifyEmailToken: deleted emailVerification token after existing user for email=${email}`,
          );
        } catch (delErr) {
          this.logger.warn(`verifyEmailToken: failed to delete token doc: ${delErr?.message}`);
        }

        return {
          success: true,
          message: 'Account existiert und ist verifiziert.',
          userId: existingUser.id,
          email,
          name: existingUser.data()?.name || '',
        };
      }

      this.logger.log(`verifyEmailToken: creating user for email: ${email}`);
      const userRef = await firestore.collection('users').add({
        email,
        password,
        name,
        emailVerified: true,
        createdAt: admin.firestore.Timestamp.fromDate(new Date()),
        loginStreak: 0,
        longestLoginStreak: 0,
        lastLoginDate: null,
        aboutMe: '',
        lessonPerformanceMatrix: [],
        testPerformanceMatrix: [],
        dictionaryEntries: [],
        favoriteGestures: [],
        avatarPath: null,
        avatarMimeType: null,
        avatarUpdatedAt: null,
      });

      this.logger.log(`verifyEmailToken: user created with ID: ${userRef.id}`);

      try {
        await docRef.delete();
        this.logger.log(
          `verifyEmailToken: deleted emailVerification token after creating user id=${userRef.id}`,
        );
      } catch (delErr) {
        this.logger.warn(
          `verifyEmailToken: failed to delete token doc after creating user: ${delErr?.message}`,
        );
      }

      return {
        success: true,
        message: 'Email erfolgreich verifiziert',
        userId: userRef.id,
        email,
        name,
      };
    } catch (err) {
      this.logger.error(`verifyEmailToken ERROR: ${err?.message}`, err?.stack);
      return {
        success: false,
        error: 'SERVER_ERROR',
        message: 'Server Fehler',
        email: '',
      };
    }
  }

  // Google-Login mit Login-Streak
  async loginWithGoogle(googleUser: { email: string; name: string; googleId: string }) {
    this.logger.log(
      `loginWithGoogle start: email=${googleUser.email}, googleId=${googleUser.googleId}`,
    );

    if (!googleUser.email) {
      this.logger.warn('loginWithGoogle: missing email from Google profile');
      throw new BadRequestException('Google account has no email');
    }

    const firestore = this.firebaseApp.firestore();
    this.logger.log('loginWithGoogle: got firestore instance');

    const now = new Date();
    let userId: string | null = null;
    let loginStreak = 0;
    let longestLoginStreak = 0;

    // nach googleId
    const googleIdQuery = await firestore
      .collection('users')
      .where('googleId', '==', googleUser.googleId)
      .get();

    if (!googleIdQuery.empty) {
      const userDoc = googleIdQuery.docs[0];
      const user = userDoc.data() as any;
      userId = userDoc.id;
        await this.ensureUserCollections(userDoc);

      const streakData = this.updateLoginStreak(user, now);

      await userDoc.ref.update({
        ...streakData,
      });

      loginStreak = streakData.loginStreak;
      longestLoginStreak = streakData.longestLoginStreak;

      this.logger.log(
        `loginWithGoogle: found user by googleId=${googleUser.googleId}, userId=${userId}`,
      );
    } else {
      // nach email
      const emailQuery = await firestore
        .collection('users')
        .where('email', '==', googleUser.email)
        .get();

      if (!emailQuery.empty) {
        const userDoc = emailQuery.docs[0];
        const user = userDoc.data() as any;
        userId = userDoc.id;
        await this.ensureUserCollections(userDoc);

        const streakData = this.updateLoginStreak(user, now);

        await userDoc.ref.update({
          googleId: googleUser.googleId,
          ...streakData,
        });

        loginStreak = streakData.loginStreak;
        longestLoginStreak = streakData.longestLoginStreak;

        this.logger.log(
          `loginWithGoogle: found existing user by email=${googleUser.email}, userId=${userId}`,
        );
      } else {
        // neuer User
        const streakData = this.updateLoginStreak(
          { lastLoginDate: null, loginStreak: 0, longestLoginStreak: 0 },
          now,
        );

        this.logger.log(`loginWithGoogle: creating new user for email=${googleUser.email}`);

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

        this.logger.log(`loginWithGoogle: new user created with ID=${userId}`);
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

  // Apple-Login mit Login-Streak
  async loginWithApple(appleUser: { email: string; name: string; appleId: string }) {
    this.logger.log(
      `loginWithApple start: email=${appleUser.email}, appleId=${appleUser.appleId}`,
    );

    /**
     * Apple liefert email (und name) oft nur beim allerersten Login/Consent.
     * Deshalb: Primär über appleId matchen; email nur für Merge/Create verwenden. [web:31]
     */
    if (!appleUser.appleId) {
      this.logger.warn('loginWithApple: missing appleId from Apple profile');
      throw new BadRequestException('Apple login has no appleId');
    }

    const firestore = this.firebaseApp.firestore();
    this.logger.log('loginWithApple: got firestore instance');

    const now = new Date();
    let userId: string | null = null;
    let loginStreak = 0;
    let longestLoginStreak = 0;

    // 1) Zuerst appleId (funktioniert auch ohne email) [web:31]
    const appleIdQuery = await firestore
      .collection('users')
      .where('appleId', '==', appleUser.appleId)
      .get();

    if (!appleIdQuery.empty) {
      const userDoc = appleIdQuery.docs[0];
      const user = userDoc.data() as any;
      userId = userDoc.id;
      await this.ensureUserCollections(userDoc);

      const streakData = this.updateLoginStreak(user, now);

      await userDoc.ref.update({
        ...streakData,
      });

      loginStreak = streakData.loginStreak;
      longestLoginStreak = streakData.longestLoginStreak;

      this.logger.log(
        `loginWithApple: found user by appleId=${appleUser.appleId}, userId=${userId}`,
      );
    } else {
      // 2) Kein user via appleId → dann brauchen wir email für Merge/Create
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
        await this.ensureUserCollections(userDoc);

        const streakData = this.updateLoginStreak(user, now);

        await userDoc.ref.update({
          appleId: appleUser.appleId,
          ...streakData,
        });

        loginStreak = streakData.loginStreak;
        longestLoginStreak = streakData.longestLoginStreak;

        this.logger.log(
          `loginWithApple: found existing user by email=${appleUser.email}, userId=${userId}`,
        );
      } else {
        const streakData = this.updateLoginStreak(
          { lastLoginDate: null, loginStreak: 0, longestLoginStreak: 0 },
          now,
        );

        this.logger.log(
          `loginWithApple: creating new user for email=${appleUser.email}`,
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

        this.logger.log(`loginWithApple: new user created with ID=${userId}`);
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

  // Profil aktualisieren (Name + AboutMe)
  async updateProfile(userId: string, dto: UpdateProfileDto) {
    this.logger.log(`updateProfile start: userId=${userId}, dto=${JSON.stringify(dto)}`);

    const firestore = this.firebaseApp.firestore();
    const userRef = firestore.collection('users').doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      this.logger.warn(`updateProfile: user not found: ${userId}`);
      throw new BadRequestException('User not found');
    }

    const updates: Record<string, any> = {};

    if (dto.name && dto.name.trim()) {
      const newName = dto.name.trim();

      const nameRef = firestore.collection('users').where('name', '==', newName);
      const nameSnapshot = await nameRef.get();

      const conflict = nameSnapshot.docs.find((d) => d.id !== userId);
      if (conflict) {
        this.logger.warn(`updateProfile: name already in use by other user: ${newName}`);
        throw new BadRequestException('Dieser Benutzername ist bereits vergeben');
      }

      this.validateNameAgainstForbiddenWords(newName);

      updates.name = newName;
    }

    if (typeof dto.aboutMe === 'string') {
      updates.aboutMe = dto.aboutMe.trim();
    }

    if (Object.keys(updates).length === 0) {
      this.logger.log('updateProfile: nothing to update');
      return { success: true, message: 'Nothing to update' };
    }

    await userRef.update(updates);

    this.logger.log(`updateProfile: updated user ${userId}`);
    return {
      success: true,
      message: 'Profil aktualisiert',
      updates,
    };
  }

  /**
   * Returns the current login streak information for a given userId.
   * Used by the frontend to display the user's current streak without
   * modifying it.
   */
  async getStreak(userId: string) {
    this.logger.log(`getStreak start: userId=${userId}`);
    const firestore = this.firebaseApp.firestore();
    const userRef = firestore.collection('users').doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      this.logger.warn(`getStreak: user not found: ${userId}`);
      throw new BadRequestException('User not found');
    }

    const user = userDoc.data() as any;
    return {
      success: true,
      loginStreak: (user && (user.loginStreak as number)) || 0,
      longestLoginStreak: (user && (user.longestLoginStreak as number)) || 0,
      lastLoginDate: (user && user.lastLoginDate) || null,
    };
  }
}
