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
import * as nodemailer from 'nodemailer';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @Inject('FIREBASE_APP') private firebaseApp: admin.app.App,
    private jwtService: JwtService,
  ) {}

  async signup(signupData: SignupDto) {
    this.logger.log(`signup start: ${JSON.stringify(signupData)}`);

    const { email, password, name } = signupData;

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
        name,
        email,
        password: hashedPassword,
        createdAt: admin.firestore.Timestamp.fromDate(createdAt),
        expiresAt: admin.firestore.Timestamp.fromDate(expiresAt),
      });

      this.logger.log(
        'signup: email verification document created with token as document ID',
      );

      await this.sendVerificationEmail(email, token);
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

    const { identifier, password } = credentials;

    try {
      const firestore = this.firebaseApp.firestore();
      this.logger.log('login: got firestore instance');

      const isEmail = identifier.includes('@');

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
      const user = userDoc.data();
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
      const token = tokenDoc.data();
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
      let decodedToken = token;
      try {
        decodedToken = decodeURIComponent(token);
      } catch {}

      let docRef = firestore
        .collection('emailVerifications')
        .doc(decodedToken);
      let doc = await docRef.get();

      if (!doc.exists && decodedToken !== token) {
        docRef = firestore.collection('emailVerifications').doc(token);
        doc = await docRef.get();
      }

      if (!doc.exists) {
        this.logger.error(`verifyEmailToken: document not found`);
        return {
          success: true,
          error: 'INVALID_TOKEN',
          message: 'Ungültiger oder abgelaufener Token',
          name: 'Nutzer',
          email: '',
        };
      }

      const tokenData = doc.data();
      if (!tokenData) {
        this.logger.warn(`verifyEmailToken: document has no data`);
        await docRef.delete().catch(() => {});
        return {
          success: true,
          error: 'INVALID_TOKEN_DATA',
          message: 'Ungültige Token-Daten',
          name: 'Nutzer',
          email: '',
        };
      }

      const now = new Date();
      let expiresAt: Date;

      if (
        tokenData.expiresAt &&
        typeof tokenData.expiresAt.toDate === 'function'
      ) {
        expiresAt = tokenData.expiresAt.toDate();
      } else if (tokenData.expiresAt instanceof Date) {
        expiresAt = tokenData.expiresAt;
      } else if (typeof tokenData.expiresAt === 'string') {
        expiresAt = new Date(tokenData.expiresAt);
      } else {
        await docRef.delete().catch(() => {});
        return {
          success: true,
          error: 'INVALID_TOKEN_FORMAT',
          message: 'Ungültiges Token-Format',
          name: 'Nutzer',
          email: '',
        };
      }

      if (expiresAt.getTime() < now.getTime()) {
        this.logger.warn(`verifyEmailToken: token expired`);
        await docRef.delete().catch(() => {});
        return {
          success: true,
          error: 'TOKEN_EXPIRED',
          message: 'Token abgelaufen',
          email: tokenData.email || '',
          name: tokenData.name || 'Nutzer',
        };
      }

      const email = tokenData.email;
      const name = tokenData.name;
      const password = tokenData.password;

      if (!email || !name || !password) {
        this.logger.warn(`verifyEmailToken: missing required fields`);
        await docRef.delete().catch(() => {});
        return {
          success: true,
          error: 'MISSING_FIELDS',
          message: 'Fehlende Benutzerdaten',
          name: name || 'Nutzer',
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
        const existingUserData = existingUser.data();
        this.logger.log(`verifyEmailToken: existing user name: ${existingUserData.name}`);
        await docRef.delete().catch(() => {});
        return {
          success: true,
          message: 'Account existiert und ist verifiziert.',
          userId: existingUser.id,
          email: email,
          name: existingUserData.name || name,
        };
      }

      this.logger.log(`verifyEmailToken: creating user for email: ${email}`);
      const userRef = await firestore.collection('users').add({
        name,
        email,
        password,
        emailVerified: true,
        createdAt: admin.firestore.Timestamp.fromDate(new Date()),
        lastLogin: null,
      });

      this.logger.log(
        `verifyEmailToken: user created with ID: ${userRef.id}`,
      );

      docRef.delete().catch(() => {});

      const newUserCheck = await firestore
        .collection('users')
        .where('email', '==', email)
        .get();

      if (!newUserCheck.empty) {
        const newUser = newUserCheck.docs[0];
        const newUserData = newUser.data();
        this.logger.log(
          `verifyEmailToken: verified new user in database with ID: ${newUser.id}, name: ${newUserData.name}`,
        );
        return {
          success: true,
          message: 'Email erfolgreich verifiziert',
          userId: newUser.id,
          email: email,
          name: newUserData.name,
        };
      }

      this.logger.warn(
        `verifyEmailToken: fallback return after user creation`,
      );
      return {
        success: true,
        message: 'Email erfolgreich verifiziert',
        userId: userRef.id,
        email: email,
        name: name,
      };
    } catch (err) {
      this.logger.error(`verifyEmailToken ERROR: ${err?.message}`, err?.stack);
      return {
        success: true,
        error: 'SERVER_ERROR',
        message: 'Server Fehler',
        name: 'Nutzer',
        email: '',
      };
    }
  }

  private async sendVerificationEmail(email: string, token: string) {
    this.logger.log(`sendVerificationEmail start: email=${email}`);

    const encodedToken = encodeURIComponent(token);
    this.logger.log(`sendVerificationEmail: raw token=${token}`);
    this.logger.log(`sendVerificationEmail: encoded token=${encodedToken}`);

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
      pool: true,
      maxConnections: 1,
      tls: {
        rejectUnauthorized: false,
      },
    });

    const verifyUrl = `https://signly-test-346744939652.europe-west1.run.app/auth/verify?token=${encodedToken}`;
    this.logger.log(`sendVerificationEmail: verify URL: ${verifyUrl}`);

    const mailOptions = {
      from: `"Signly" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Bestätige deine E-Mail-Adresse für Signly',
      html: `<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
              <h2 style="color: #333;">Willkommen bei Signly!</h2>
              <p>Bitte bestätige deine E-Mail-Adresse, indem du auf den folgenden Link klickst:</p>
              <p style="margin: 30px 0;">
                <a href="${verifyUrl}" 
                   style="background-color: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">
                  E-Mail bestätigen
                </a>
              </p>
              <p><strong>Der Link ist 15 Minuten gültig.</strong></p>
              <p style="color: #999; font-size: 12px; border-top: 1px solid #eee; padding-top: 20px; margin-top: 30px;">
                Wenn du dich nicht bei Signly registriert hast, ignoriere diese E-Mail bitte.
              </p>
            </div>`,
      headers: {
        'X-Priority': '1',
        Importance: 'high',
      },
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      this.logger.log(
        `sendVerificationEmail: mail sent to ${email}, messageId: ${info.messageId}`,
      );
      return info;
    } catch (error) {
      this.logger.error(
        `sendVerificationEmail ERROR: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }
}
