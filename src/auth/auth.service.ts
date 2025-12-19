import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
  Inject,
  Logger,
} from '@nestjs/common';
import { SignupDto } from './dto/signup.dto';
import * as admin from 'firebase-admin';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { MailerService } from './mailer.service';
import words from './words.json';
import { UpdateProfileDto } from './update-profile.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

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
      this.logger.warn(
        `signup: forbidden name "${name}" contains "${hit}"`,
      );
      throw new BadRequestException(
        'Dieser Benutzername ist nicht erlaubt',
      );
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
          Date.UTC(
            lastDate.getFullYear(),
            lastDate.getMonth(),
            lastDate.getDate(),
          )) /
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

  async signup(signupData: SignupDto) {
    this.logger.log(`signup start: ${JSON.stringify(signupData)}`);

    const rawNameFromDto =
      (signupData && (signupData as any).name) ||
      (signupData && (signupData as any).username) ||
      (signupData && (signupData as any).displayName) ||
      '';
    const name =
      (typeof rawNameFromDto === 'string' ? rawNameFromDto.trim() : '').trim();

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
      this.logger.warn(
        `signup: missing name (raw: ${JSON.stringify(rawNameFromDto)})`,
      );
      throw new BadRequestException('Name ist erforderlich');
    }

    // Name gegen Schimpfwörter prüfen
    this.validateNameAgainstForbiddenWords(name);

    try {
      const firestore = this.firebaseApp.firestore();
      this.logger.log('signup: got firestore instance');

      const emailRef = firestore.collection('users').where('email', '==', email);
      const emailSnapshot = await emailRef.get();
      this.logger.log(
        `signup: existing users with email=${email}: ${emailSnapshot.size}`,
      );

      if (!emailSnapshot.empty) {
        this.logger.warn(`signup: email already in use: ${email}`);
        throw new BadRequestException('Diese Email hat bereits einen Account');
      }

      const nameRef = firestore.collection('users').where('name', '==', name);
      const nameSnapshot = await nameRef.get();
      this.logger.log(
        `signup: existing users with name=${name}: ${nameSnapshot.size}`,
      );

      if (!nameSnapshot.empty) {
        this.logger.warn(`signup: name already in use: ${name}`);
        throw new BadRequestException(
          'Dieser Benutzername ist bereits vergeben',
        );
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      this.logger.log('signup: password hashed');

      const oldTokensQuery = await firestore
        .collection('emailVerifications')
        .where('email', '==', email)
        .get();

      if (!oldTokensQuery.empty) {
        this.logger.log(
          `signup: deleting ${oldTokensQuery.size} old tokens for ${email}`,
        );
        const deletePromises = oldTokensQuery.docs.map((doc) =>
          doc.ref.delete(),
        );
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

      this.logger.log(
        'signup: email verification document created with token as document ID',
      );

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

      const isEmail =
        typeof identifier === 'string' && identifier.includes('@');

      const userQuery = isEmail
        ? firestore.collection('users').where('email', '==', identifier)
        : firestore.collection('users').where('name', '==', identifier);

      const snapshot = await userQuery.get();
      this.logger.log(
        `login: users found with ${
          isEmail ? 'email' : 'name'
        }=${identifier}: ${snapshot.size}`,
      );

      if (snapshot.empty) {
        this.logger.warn(
          `login: no user found for ${
            isEmail ? 'email' : 'name'
          }=${identifier}`,
        );
        throw new UnauthorizedException('Wrong credentials');
      }

      const userDoc = snapshot.docs[0];
      const user = userDoc.data() as any;
      this.logger.log(
        `login: userDoc id=${userDoc.id}, user=${JSON.stringify(user)}`,
      );

      const passwordMatch = await bcrypt.compare(password, user.password);
      this.logger.log(`login: passwordMatch=${passwordMatch}`);

      if (!passwordMatch) {
        this.logger.warn(
          `login: wrong password for ${
            isEmail ? 'email' : 'name'
          }=${identifier}`,
        );
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
      this.logger.log(
        `refreshTokens: tokenDoc id=${tokenDoc.id}, userId=${token.userId}`,
      );

      const tokens = await this.generateUserToken(token.userId);
      this.logger.log('refreshTokens: new tokens generated');
      return tokens;
    } catch (err) {
      this.logger.error(
        `refreshTokens internal error: ${err?.message}`,
        err?.stack,
      );
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

      this.logger.log(
        `verifyEmailToken: tokenData.email='${email}', name='${name}'`,
      );

      if (!email || !password) {
        this.logger.warn(`verifyEmailToken: missing required fields`);
        return {
          success: false,
          error: 'MISSING_FIELDS',
          message: 'Fehlende Benutzerdaten',
          email: email || '',
        };
      }

      const userQuery = await firestore
        .collection('users')
        .where('email', '==', email)
        .get();

      if (!userQuery.empty) {
        this.logger.log(
          `verifyEmailToken: user already exists for email: ${email}`,
        );
        const existingUser = userQuery.docs[0];
        try {
          await docRef.delete();
          this.logger.log(
            `verifyEmailToken: deleted emailVerification token after existing user for email=${email}`,
          );
        } catch (delErr) {
          this.logger.warn(
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

      this.logger.log(
        `verifyEmailToken: creating user for email: ${email}`,
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
      });

      this.logger.log(
        `verifyEmailToken: user created with ID: ${userRef.id}`,
      );

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
  async loginWithGoogle(googleUser: {
    email: string;
    name: string;
    googleId: string;
  }) {
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

        this.logger.log(
          `loginWithGoogle: creating new user for email=${googleUser.email}`,
        );

        const newUserRef = await firestore.collection('users').add({
          email: googleUser.email,
          name: googleUser.name || googleUser.email,
          googleId: googleUser.googleId,
          emailVerified: true,
          password: null,
          createdAt: admin.firestore.Timestamp.fromDate(now),
          aboutMe: '',
          ...streakData,
        });

        userId = newUserRef.id;
        loginStreak = streakData.loginStreak;
        longestLoginStreak = streakData.longestLoginStreak;

        this.logger.log(
          `loginWithGoogle: new user created with ID=${userId}`,
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

  // Profil aktualisieren (Name + AboutMe)
  async updateProfile(userId: string, dto: UpdateProfileDto) {
    this.logger.log(
      `updateProfile start: userId=${userId}, dto=${JSON.stringify(dto)}`,
    );

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

      const nameRef = firestore
        .collection('users')
        .where('name', '==', newName);
      const nameSnapshot = await nameRef.get();

      const conflict = nameSnapshot.docs.find((d) => d.id !== userId);
      if (conflict) {
        this.logger.warn(
          `updateProfile: name already in use by other user: ${newName}`,
        );
        throw new BadRequestException(
          'Dieser Benutzername ist bereits vergeben',
        );
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
}
