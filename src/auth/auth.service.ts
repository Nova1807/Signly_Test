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
  ) {
    this.logger.log('AuthService constructed');
    const fs = this.firebaseApp.firestore();
    this.logger.log(
      'AuthService firestore config: ' +
        JSON.stringify({
          projectId: this.firebaseApp.options.projectId,
          databaseId: (fs as any)._databaseId,
        }),
    );
  }

  async signup(signupData: SignupDto) {
    this.logger.log(`signup start: ${JSON.stringify(signupData)}`);

    const { email, password, name } = signupData;

    try {
      const firestore = this.firebaseApp.firestore();
      this.logger.log('signup: got firestore instance');

      // 1. Email prüfen
      const emailRef = firestore.collection('users').where('email', '==', email);
      const emailSnapshot = await emailRef.get();
      this.logger.log(
        `signup: existing users with email=${email}: ${emailSnapshot.size}`,
      );

      if (!emailSnapshot.empty) {
        this.logger.warn(`signup: email already in use: ${email}`);
        throw new BadRequestException('Diese Email hat bereits einen Account');
      }

      // 2. Username prüfen
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

      // 3. Passwort hashen
      const hashedPassword = await bcrypt.hash(password, 10);
      this.logger.log('signup: password hashed');

      // 4. Verification-Token erzeugen und in emailVerifications speichern
      const token = uuidv4();
      const createdAt = new Date();
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 24); // 24h gültig

      await firestore.collection('emailVerifications').doc(token).set({
        name,
        email,
        password: hashedPassword,
        createdAt,
        expiresAt,
      });

      this.logger.log('signup: email verification document created');

      // 5. Verifizierungs-Mail senden
      await this.sendVerificationEmail(email, token);
      this.logger.log('signup: verification email sent');

      return { success: true };
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

    await firestore.collection('refreshTokens').add({ token, userId, expiryDate });
    this.logger.log('storeRefreshToken: refresh token document created');
  }

  async verifyEmailToken(token: string) {
    this.logger.log(`verifyEmailToken start: token=${token}`);
    const firestore = this.firebaseApp.firestore();

    const docRef = firestore.collection('emailVerifications').doc(token);
    const doc = await docRef.get();

    if (!doc.exists) {
      this.logger.warn(`verifyEmailToken: token not found`);
      throw new BadRequestException('Invalid token');
    }

    const data = doc.data();
    if (!data) {
      this.logger.warn(`verifyEmailToken: token data undefined`);
      await docRef.delete();
      throw new BadRequestException('Invalid token');
    }

    const now = new Date();

    // expiresAt kann Date oder Firestore Timestamp sein
    let expiresAt: Date | null = null;
    const rawExpiresAt = (data as any).expiresAt;

    if (rawExpiresAt instanceof Date) {
      expiresAt = rawExpiresAt;
    } else if (rawExpiresAt && typeof rawExpiresAt.toDate === 'function') {
      expiresAt = rawExpiresAt.toDate();
    }

    if (!expiresAt || expiresAt < now) {
      this.logger.warn(`verifyEmailToken: token expired`);
      await docRef.delete();
      throw new BadRequestException('Token expired');
    }

    const email = (data as any).email;
    const name = (data as any).name;
    const password = (data as any).password;

    if (!email || !name || !password) {
      this.logger.warn(`verifyEmailToken: missing user fields in token data`);
      await docRef.delete();
      throw new BadRequestException('Invalid token data');
    }

    const emailSnapshot = await firestore
      .collection('users')
      .where('email', '==', email)
      .get();

    if (!emailSnapshot.empty) {
      this.logger.warn(`verifyEmailToken: email already in use: ${email}`);
      await docRef.delete();
      throw new BadRequestException('Email already verified');
    }

    await firestore.collection('users').add({
      name,
      email,
      password,
    });

    await docRef.delete();

    this.logger.log(`verifyEmailToken: user created and token deleted`);
    return { success: true };
  }

  private async sendVerificationEmail(email: string, token: string) {
    this.logger.log(`sendVerificationEmail start: email=${email}`);

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER, // z.B. signlylernapp@gmail.com
        pass: process.env.EMAIL_PASS, // 16-stelliges App-Passwort
      },
    });

    const verifyUrl = `https://signly-test-346744939652.europe-west1.run.app/auth/verify?token=${token}`;

    await transporter.sendMail({
      from: `"Signly" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Bestätige deine E-Mail-Adresse',
      html: `<p>Bitte bestätige deine E-Mail, indem du auf diesen Link klickst:</p>
             <p><a href="${verifyUrl}">${verifyUrl}</a></p>`,
    });

    this.logger.log(`sendVerificationEmail: mail sent to ${email}`);
  }
}
