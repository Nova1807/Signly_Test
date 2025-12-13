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
      // gleicher Typ wie bei "Benutzername vergeben", andere Nachricht
      throw new BadRequestException(
        'Dieser Benutzername ist nicht erlaubt',
      );
    }
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

    // NEU: Name gegen Schimpfwörter prüfen
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

      const tokens = await this.generateUserToken(userDoc.id);
      this.logger.log('login: tokens generated');
      return tokens;
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
        lastLogin: null,
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

  // NEU: Google-Login
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

    const googleIdQuery = await firestore
      .collection('users')
      .where('googleId', '==', googleUser.googleId)
      .get();

    let userId: string | null = null;

    if (!googleIdQuery.empty) {
      const userDoc = googleIdQuery.docs[0];
      userId = userDoc.id;
      this.logger.log(
        `loginWithGoogle: found user by googleId=${googleUser.googleId}, userId=${userId}`,
      );
    } else {
      const emailQuery = await firestore
        .collection('users')
        .where('email', '==', googleUser.email)
        .get();

      if (!emailQuery.empty) {
        const userDoc = emailQuery.docs[0];
        userId = userDoc.id;
        this.logger.log(
          `loginWithGoogle: found existing user by email=${googleUser.email}, userId=${userId}`,
        );

        await userDoc.ref.update({
          googleId: googleUser.googleId,
          lastLogin: admin.firestore.Timestamp.fromDate(new Date()),
        });
      } else {
        this.logger.log(
          `loginWithGoogle: creating new user for email=${googleUser.email}`,
        );

        const newUserRef = await firestore.collection('users').add({
          email: googleUser.email,
          name: googleUser.name || googleUser.email,
          googleId: googleUser.googleId,
          emailVerified: true,
          password: null,
          createdAt: admin.firestore.Timestamp.fromDate(new Date()),
          lastLogin: admin.firestore.Timestamp.fromDate(new Date()),
        });

        userId = newUserRef.id;
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
    return tokens;
  }
}
