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
        createdAt: admin.firestore.Timestamp.fromDate(createdAt),
        expiresAt: admin.firestore.Timestamp.fromDate(expiresAt),
      });

      this.logger.log(
        'signup: email verification document created with token as document ID',
      );

      await this.sendVerificationEmail(email, token, name);
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

      const email: string =
        (tokenData.email && String(tokenData.email)) || '';
      const password = tokenData.password;

      this.logger.log(
        `verifyEmailToken: tokenData.email='${email}'`,
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
        return {
          success: true,
          message: 'Account existiert und ist verifiziert.',
          userId: existingUser.id,
          email,
        };
      }

      this.logger.log(
        `verifyEmailToken: creating user for email: ${email}`,
      );
      const userRef = await firestore.collection('users').add({
        email,
        password,
        emailVerified: true,
        createdAt: admin.firestore.Timestamp.fromDate(new Date()),
        lastLogin: null,
      });

      this.logger.log(
        `verifyEmailToken: user created with ID: ${userRef.id}`,
      );

      return {
        success: true,
        message: 'Email erfolgreich verifiziert',
        userId: userRef.id,
        email,
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

  private async sendVerificationEmail(
    email: string,
    token: string,
    name?: string,
  ) {
    this.logger.log(
      `sendVerificationEmail start: email=${email}, name='${name || ''}'`,
    );

    const encodedToken = encodeURIComponent(token);
    const encodedName = encodeURIComponent(name || '');
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

    const baseVerifyUrl =
      'https://signly-test-346744939652.europe-west1.run.app/auth/verify';
    const verifyUrl = `${baseVerifyUrl}?token=${encodedToken}${
      encodedName ? `&name=${encodedName}` : ''
    }`;
    this.logger.log(`sendVerificationEmail: verify URL: ${verifyUrl}`);

    const baseUrl = 'https://signly-test-346744939652.europe-west1.run.app';
    const assetsBaseUrl = `${baseUrl}/email-assets`;

    const mailOptions = {
      from: `"Signly" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Bestätige deine E-Mail-Adresse für Signly',
      html: `
      <!DOCTYPE html>
      <html lang="de">
        <body style="margin:0; padding:0; background-color:#f4fbff;">
          <table width="100%" cellspacing="0" cellpadding="0" style="padding:24px 0;">
            <tr>
              <td align="center">
                <table width="100%" cellspacing="0" cellpadding="0" 
                       style="max-width:600px; background-color:#ffffff; border-radius:16px; 
                              box-shadow:0 10px 25px rgba(0,0,0,0.06); padding:24px 24px 28px;">
                  <tr>
                    <td align="center" style="padding-bottom:16px;">
                      <!-- Logo kleiner -->
                      <img src="${assetsBaseUrl}/Logo.png"
                           alt="Signly Logo"
                           width="80"
                           style="display:block; margin-bottom:8px;" />
                      <!-- Maskottchen größer -->
                      <img src="${assetsBaseUrl}/Maskotchen.png"
                           alt="Signly Maskottchen"
                           width="220"
                           style="display:block;" />
                    </td>
                  </tr>

                  <tr>
                    <td align="center" 
                        style="font-family:Arial, sans-serif; padding:8px 16px 4px;">
                      <h1 style="margin:0; font-size:22px; color:#073b4c;">
                        Willkommen bei Signly${name ? ', ' + name : ''}!
                      </h1>
                    </td>
                  </tr>

                  <tr>
                    <td align="center" 
                        style="font-family:Arial, sans-serif; padding:8px 32px 16px;">
                      <p style="margin:0; font-size:14px; line-height:1.6; color:#4a5568;">
                        Fast geschafft! Bitte bestätige deine E-Mail-Adresse, 
                        damit dein Signly-Account aktiviert werden kann.
                      </p>
                    </td>
                  </tr>

                  <tr>
                    <td align="center" style="padding:20px 16px 4px;">
                      <a href="${verifyUrl}"
                         style="display:inline-block; background:linear-gradient(90deg,#73c5f5,#a6f9fd);
                                color:#ffffff; font-family:Arial, sans-serif; font-size:15px; 
                                font-weight:bold; text-decoration:none; padding:12px 28px; 
                                border-radius:999px;">
                        E-Mail-Adresse bestätigen
                      </a>
                    </td>
                  </tr>

                  <tr>
                    <td align="center" 
                        style="font-family:Arial, sans-serif; padding:12px 24px 16px;">
                      <p style="margin:0; font-size:12px; color:#718096;">
                        Der Bestätigungslink ist <strong>15 Minuten</strong> gültig.
                      </p>
                    </td>
                  </tr>

                  <tr>
                    <td style="font-family:Arial, sans-serif; padding:8px 24px 16px;">
                      <p style="margin:0 0 4px; font-size:12px; color:#4a5568;">
                        Falls der Button nicht funktioniert, kopiere diesen Link in deinen Browser:
                      </p>
                      <p style="margin:0; font-size:11px; color:#2d3748; word-break:break-all;">
                        ${verifyUrl}
                      </p>
                    </td>
                  </tr>

                  <tr>
                    <td style="font-family:Arial, sans-serif; padding:16px 24px 8px;">
                      <p style="margin:0; font-size:11px; color:#a0aec0;">
                        Wenn du dich nicht bei Signly registriert hast, 
                        kannst du diese E-Mail ignorieren.
                      </p>
                    </td>
                  </tr>

                  <tr>
                    <td align="center" 
                        style="font-family:Arial, sans-serif; padding:12px 16px 0; 
                               border-top:1px solid #e2e8f0;">
                      <p style="margin:6px 0 0; font-size:11px; color:#a0aec0;">
                        © ${new Date().getFullYear()} Signly. Alle Rechte vorbehalten.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </body>
      </html>
      `,
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
        `sendVerificationEmail ERROR: ${error?.message}`,
        error?.stack,
      );
      throw error;
    }
  }
}
