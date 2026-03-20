import { BadRequestException, Logger } from '@nestjs/common';
import * as admin from 'firebase-admin';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { SignupDto } from '../dto/signup.dto';
import { UpdateProfileDto } from '../update-profile.dto';
import { MailerService } from '../mailer.service';
import {
  formatLogContext,
  hasValue,
  maskEmail,
  maskId,
  maskToken,
} from '../../common/logging/redaction';

export interface AccountManagerOptions {
  firebaseApp: admin.app.App;
  logger: Logger;
  mailerService: MailerService;
  verificationCleanupBatchSize: number;
  forbiddenWords: string[];
}

export class AccountManager {
  constructor(private readonly options: AccountManagerOptions) {}

  private get firestore() {
    return this.options.firebaseApp.firestore();
  }

  private validateNameAgainstForbiddenWords(name: string): void {
    const nameLower = (name || '').toLowerCase();
    const hit = (this.options.forbiddenWords || []).find((word) => {
      const w = word?.toLowerCase?.() ?? '';
      if (!w) return false;
      return nameLower.includes(w);
    });

    if (hit) {
      this.options.logger.warn(`signup: forbidden name "${name}" contains "${hit}"`);
      throw new BadRequestException('Dieser Benutzername ist nicht erlaubt');
    }
  }

  private async cleanupExpiredEmailVerificationTokens(): Promise<void> {
    const firestore = this.firestore;
    const nowTimestamp = admin.firestore.Timestamp.fromDate(new Date());
    let totalDeleted = 0;

    while (true) {
      const snapshot = await firestore
        .collection('emailVerifications')
        .where('expiresAt', '<=', nowTimestamp)
        .limit(this.options.verificationCleanupBatchSize)
        .get();

      if (snapshot.empty) {
        break;
      }

      const batch = firestore.batch();
      snapshot.docs.forEach((doc) => batch.delete(doc.ref));
      await batch.commit();
      totalDeleted += snapshot.size;

      if (snapshot.size < this.options.verificationCleanupBatchSize) {
        break;
      }
    }

    if (totalDeleted > 0) {
      this.options.logger.log(
        `cleanupExpiredEmailVerificationTokens: deleted ${totalDeleted} expired docs`,
      );
    }
  }

  async signup(signupData: SignupDto) {
    await this.cleanupExpiredEmailVerificationTokens();

    const rawNameFromDto =
      (signupData && (signupData as any).name) ||
      (signupData && (signupData as any).username) ||
      (signupData && (signupData as any).displayName) ||
      '';
    const name = (typeof rawNameFromDto === 'string' ? rawNameFromDto.trim() : '').trim();
    const { email, password } = signupData as any;

    this.options.logger.log(
      'signup start' +
        formatLogContext({
          email: maskEmail(email),
          hasPassword: hasValue(password),
          nameLength: name.length,
        }),
    );

    if (!email || typeof email !== 'string' || !email.trim()) {
      this.options.logger.warn('signup: missing email');
      throw new BadRequestException('Email ist erforderlich');
    }
    if (!password || typeof password !== 'string' || !password.trim()) {
      this.options.logger.warn('signup: missing password');
      throw new BadRequestException('Passwort ist erforderlich');
    }
    if (!name) {
      this.options.logger.warn('signup: missing name');
      throw new BadRequestException('Name ist erforderlich');
    }

    this.validateNameAgainstForbiddenWords(name);

    try {
      const firestore = this.firestore;
      this.options.logger.log('signup: got firestore instance');

      const emailRef = firestore.collection('users').where('email', '==', email);
      const emailSnapshot = await emailRef.get();
      this.options.logger.log(
        'signup: checked email availability' +
          formatLogContext({
            email: maskEmail(email),
            matches: emailSnapshot.size,
          }),
      );

      if (!emailSnapshot.empty) {
        this.options.logger.warn(
          'signup: email already in use' + formatLogContext({ email: maskEmail(email) }),
        );
        throw new BadRequestException('Diese Email hat bereits einen Account');
      }

      const nameRef = firestore.collection('users').where('name', '==', name);
      const nameSnapshot = await nameRef.get();
      this.options.logger.log(
        'signup: checked name availability' +
          formatLogContext({
            nameLength: name.length,
            matches: nameSnapshot.size,
          }),
      );

      if (!nameSnapshot.empty) {
        this.options.logger.warn(
          'signup: name already in use' +
            formatLogContext({
              nameLength: name.length,
            }),
        );
        throw new BadRequestException('Dieser Benutzername ist bereits vergeben');
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      this.options.logger.log('signup: password hashed');

      const oldTokensQuery = await firestore
        .collection('emailVerifications')
        .where('email', '==', email)
        .get();

      if (!oldTokensQuery.empty) {
        this.options.logger.log(
          'signup: deleting old verification tokens' +
            formatLogContext({
              email: maskEmail(email),
              tokens: oldTokensQuery.size,
            }),
        );
        const deletePromises = oldTokensQuery.docs.map((doc) => doc.ref.delete());
        await Promise.all(deletePromises);
      }

      const token = uuidv4();
      const createdAt = new Date();
      const expiresAt = new Date(createdAt.getTime() + 15 * 60 * 1000);

      this.options.logger.log(
        'signup: creating verification token' +
          formatLogContext({ token: maskToken(token, 'emailVerificationToken') }),
      );
      this.options.logger.log(`signup: token expires at ${expiresAt.toISOString()}`);
      this.options.logger.log(`signup: server time: ${createdAt.toISOString()}`);

      await firestore.collection('emailVerifications').doc(token).set({
        email,
        password: hashedPassword,
        name,
        createdAt: admin.firestore.Timestamp.fromDate(createdAt),
        expiresAt: admin.firestore.Timestamp.fromDate(expiresAt),
      });

      this.options.logger.log('signup: email verification document created with token as document ID');

      await this.options.mailerService.sendVerificationEmail(email, token, name);
      this.options.logger.log('signup: verification email sent');

      return {
        success: true,
        message: 'Verifizierungsmail gesendet. Bitte E-Mail innerhalb von 15 Minuten bestätigen.',
      };
    } catch (err) {
      this.options.logger.error(`signup internal error: ${err?.message}`, err?.stack);
      throw err;
    }
  }

  async verifyEmailToken(token: string): Promise<{
    success: boolean;
    error?: string;
    message: string;
    userId?: string;
    email?: string;
    name?: string;
  }> {
    this.options.logger.log(
      'verifyEmailToken start' +
        formatLogContext({
          token: maskToken(token, 'emailVerificationToken'),
        }),
    );

    const firestore = this.firestore;
    await this.cleanupExpiredEmailVerificationTokens();

    try {
      const docRef = firestore.collection('emailVerifications').doc(token);
      const doc = await docRef.get();

      if (!doc.exists) {
        this.options.logger.error(`verifyEmailToken: document not found for token`);
        return {
          success: false,
          error: 'INVALID_TOKEN',
          message: 'Ungültiger oder abgelaufener Token',
          email: '',
        };
      }

      const tokenData = doc.data() as any;
      if (!tokenData) {
        this.options.logger.warn(`verifyEmailToken: document has no data`);
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

      this.options.logger.log(
        'verifyEmailToken: payload extracted' +
          formatLogContext({
            email: maskEmail(email),
            hasPassword: hasValue(password),
            nameLength: name.length,
          }),
      );

      if (!email || !password) {
        this.options.logger.warn(`verifyEmailToken: missing required fields`);
        return {
          success: false,
          error: 'MISSING_FIELDS',
          message: 'Fehlende Benutzerdaten',
          email: email || '',
        };
      }

      const userQuery = await firestore.collection('users').where('email', '==', email).get();

      if (!userQuery.empty) {
        this.options.logger.log(
          'verifyEmailToken: user already exists' + formatLogContext({ email: maskEmail(email) }),
        );
        const existingUser = userQuery.docs[0];
        try {
          await docRef.delete();
          this.options.logger.log(
            'verifyEmailToken: deleted stale verification token' +
              formatLogContext({
                token: maskToken(token, 'emailVerificationToken'),
                email: maskEmail(email),
              }),
          );
        } catch (delErr) {
          this.options.logger.warn(
            `verifyEmailToken: failed to delete token doc: ${delErr?.message}`,
          );
        }

        return {
          success: true,
          message: 'Account existiert und ist verifiziert.',
          userId: existingUser.id,
          email,
          name: existingUser.data()?.name || '',
        };
      }

      this.options.logger.log(
        'verifyEmailToken: creating user' + formatLogContext({ email: maskEmail(email) }),
      );
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

      this.options.logger.log(
        'verifyEmailToken: user created' +
          formatLogContext({
            userId: maskId(userRef.id),
          }),
      );

      try {
        await docRef.delete();
        this.options.logger.log(
          'verifyEmailToken: deleted verification token after user creation' +
            formatLogContext({
              token: maskToken(token, 'emailVerificationToken'),
              userId: maskId(userRef.id),
            }),
        );
      } catch (delErr) {
        this.options.logger.warn(
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
      this.options.logger.error(`verifyEmailToken ERROR: ${err?.message}`, err?.stack);
      return {
        success: false,
        error: 'SERVER_ERROR',
        message: 'Server Fehler',
        email: '',
      };
    }
  }

  async updateProfile(userId: string, dto: UpdateProfileDto) {
    this.options.logger.log(
      'updateProfile start' +
        formatLogContext({
          userId: maskId(userId),
          nameProvided: hasValue(dto?.name),
          aboutMeLength:
            typeof dto?.aboutMe === 'string' ? dto.aboutMe.trim().length : undefined,
        }),
    );

    const firestore = this.firestore;
    const userRef = firestore.collection('users').doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      this.options.logger.warn(
        'updateProfile: user not found' +
          formatLogContext({
            userId: maskId(userId),
          }),
      );
      throw new BadRequestException('User not found');
    }

    const updates: Record<string, any> = {};

    if (dto.name && dto.name.trim()) {
      const newName = dto.name.trim();

      const nameRef = firestore.collection('users').where('name', '==', newName);
      const nameSnapshot = await nameRef.get();

      const conflict = nameSnapshot.docs.find((d) => d.id !== userId);
      if (conflict) {
        this.options.logger.warn(
          'updateProfile: name already in use by other user' +
            formatLogContext({
              nameLength: newName.length,
            }),
        );
        throw new BadRequestException('Dieser Benutzername ist bereits vergeben');
      }

      this.validateNameAgainstForbiddenWords(newName);

      updates.name = newName;
    }

    if (typeof dto.aboutMe === 'string') {
      updates.aboutMe = dto.aboutMe.trim();
    }

    if (Object.keys(updates).length === 0) {
      this.options.logger.log('updateProfile: nothing to update');
      return { success: true, message: 'Nothing to update' };
    }

    await userRef.update(updates);

    this.options.logger.log(
      'updateProfile: updated user' +
        formatLogContext({
          userId: maskId(userId),
          updatedFields: Object.keys(updates),
        }),
    );
    return {
      success: true,
      message: 'Profil aktualisiert',
      updates,
    };
  }
}
