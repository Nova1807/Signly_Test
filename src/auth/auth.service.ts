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

      // 1. Email in USERS collection prüfen (nicht in emailVerifications!)
      const emailRef = firestore.collection('users').where('email', '==', email);
      const emailSnapshot = await emailRef.get();
      this.logger.log(
        `signup: existing users with email=${email}: ${emailSnapshot.size}`,
      );

      if (!emailSnapshot.empty) {
        this.logger.warn(`signup: email already in use: ${email}`);
        throw new BadRequestException('Diese Email hat bereits einen Account');
      }

      // 2. Username in USERS collection prüfen
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

      // 4. Alte/ausgelaufene Token für diese Email löschen
      const oldTokensRef = firestore.collection('emailVerifications')
        .where('email', '==', email);
      const oldTokens = await oldTokensRef.get();
      
      if (!oldTokens.empty) {
        this.logger.log(`signup: deleting ${oldTokens.size} old tokens for ${email}`);
        const deletePromises = oldTokens.docs.map(doc => doc.ref.delete());
        await Promise.all(deletePromises);
      }

      // 5. NEUEN Verification-Token erzeugen (15 Minuten = 900000ms)
      const token = uuidv4();
      const createdAt = new Date();
      const expiresAt = new Date(createdAt.getTime() + 15 * 60 * 1000); // 15 Minuten

      this.logger.log(`signup: creating token ${token}, expires at ${expiresAt.toISOString()}`);

      // 6. Token in emailVerifications speichern - KEIN USER WIRD HIER ERSTELLT!
      await firestore.collection('emailVerifications').doc(token).set({
        name,
        email,
        password: hashedPassword,
        createdAt: admin.firestore.Timestamp.fromDate(createdAt), // Als Firestore Timestamp
        expiresAt: admin.firestore.Timestamp.fromDate(expiresAt), // Als Firestore Timestamp
      });

      this.logger.log('signup: email verification document created');

      // 7. Verifizierungs-Mail senden
      await this.sendVerificationEmail(email, token);
      this.logger.log('signup: verification email sent');

      return { 
        success: true, 
        message: 'Verifizierungsmail gesendet. Bitte E-Mail innerhalb von 15 Minuten bestätigen.' 
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

      // Nur in USERS collection suchen (nicht in emailVerifications)
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
      expiryDate: admin.firestore.Timestamp.fromDate(expiryDate) 
    });
    this.logger.log('storeRefreshToken: refresh token document created');
  }

  async verifyEmailToken(token: string) {
    this.logger.log(`verifyEmailToken start: token=${token}`);
    const firestore = this.firebaseApp.firestore();

    try {
      // 1. Token dokument holen
      const docRef = firestore.collection('emailVerifications').doc(token);
      const doc = await docRef.get();

      if (!doc.exists) {
        this.logger.warn(`verifyEmailToken: token not found: ${token}`);
        throw new BadRequestException('Ungültiger oder abgelaufener Token');
      }

      const data = doc.data();
      if (!data) {
        this.logger.warn(`verifyEmailToken: token data undefined for: ${token}`);
        await docRef.delete();
        throw new BadRequestException('Ungültiger Token');
      }

      // 2. Token Ablaufzeit prüfen (15 Minuten)
      const now = new Date();
      let expiresAt: Date;

      // Firestore Timestamp konvertieren
      if (data.expiresAt && typeof data.expiresAt.toDate === 'function') {
        expiresAt = data.expiresAt.toDate(); // Firestore Timestamp
      } else if (data.expiresAt instanceof Date) {
        expiresAt = data.expiresAt;
      } else if (typeof data.expiresAt === 'string') {
        expiresAt = new Date(data.expiresAt);
      } else {
        this.logger.warn(`verifyEmailToken: invalid expiresAt format: ${JSON.stringify(data.expiresAt)}`);
        await docRef.delete();
        throw new BadRequestException('Ungültiger Token');
      }

      this.logger.log(`verifyEmailToken: now=${now.toISOString()}, expiresAt=${expiresAt.toISOString()}, diff=${expiresAt.getTime() - now.getTime()}ms`);

      if (now > expiresAt) {
        this.logger.warn(`verifyEmailToken: token expired: ${token}, expired ${Math.round((now.getTime() - expiresAt.getTime()) / 1000)} seconds ago`);
        
        // Token löschen
        await docRef.delete();
        
        // Alle anderen Token für diese Email löchen
        if (data.email) {
          const otherTokens = await firestore.collection('emailVerifications')
            .where('email', '==', data.email)
            .get();
          
          const deletePromises = otherTokens.docs.map(doc => doc.ref.delete());
          await Promise.all(deletePromises);
          this.logger.log(`verifyEmailToken: deleted ${otherTokens.size} other tokens for ${data.email}`);
        }
        
        throw new BadRequestException('Token abgelaufen. Bitte registriere dich erneut.');
      }

      const email = data.email;
      const name = data.name;
      const password = data.password;

      if (!email || !name || !password) {
        this.logger.warn(`verifyEmailToken: missing user fields in token data: ${JSON.stringify(data)}`);
        await docRef.delete();
        throw new BadRequestException('Ungültige Token-Daten');
      }

      // 3. Prüfen ob Email schon in USERS existiert (Double-Check)
      const emailSnapshot = await firestore
        .collection('users')
        .where('email', '==', email)
        .get();

      if (!emailSnapshot.empty) {
        this.logger.warn(`verifyEmailToken: email already registered in users: ${email}`);
        await docRef.delete();
        
        // Alle Token für diese Email löschen
        const allTokens = await firestore.collection('emailVerifications')
          .where('email', '==', email)
          .get();
        
        const deletePromises = allTokens.docs.map(doc => doc.ref.delete());
        await Promise.all(deletePromises);
        
        throw new BadRequestException('Diese Email ist bereits registriert');
      }

      // 4. JETZT ERST User in USERS collection erstellen
      const userRef = await firestore.collection('users').add({
        name,
        email,
        password,
        emailVerified: true,
        createdAt: admin.firestore.Timestamp.fromDate(new Date()),
        lastLogin: null
      });

      this.logger.log(`verifyEmailToken: user created with ID: ${userRef.id} for email: ${email}`);

      // 5. Verwendeten Token löschen
      await docRef.delete();
      
      // 6. Alle anderen Token für diese Email löschen (falls mehrere existieren)
      const otherTokens = await firestore.collection('emailVerifications')
        .where('email', '==', email)
        .get();
      
      if (!otherTokens.empty) {
        const deletePromises = otherTokens.docs.map(doc => doc.ref.delete());
        await Promise.all(deletePromises);
        this.logger.log(`verifyEmailToken: deleted ${otherTokens.size} remaining tokens for ${email}`);
      }

      this.logger.log(`verifyEmailToken: successfully verified email ${email}`);
      return { 
        success: true, 
        message: 'Email erfolgreich verifiziert! Du kannst dich jetzt einloggen.',
        userId: userRef.id 
      };
    } catch (err) {
      this.logger.error(`verifyEmailToken internal error: ${err?.message}`, err?.stack);
      throw err;
    }
  }

  private async sendVerificationEmail(email: string, token: string) {
    this.logger.log(`sendVerificationEmail start: email=${email}, token=${token}`);

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
      // Optionen für bessere Zustellung
      pool: true,
      maxConnections: 1,
      tls: {
        rejectUnauthorized: false
      }
    });

    const verifyUrl = `https://signly-test-346744939652.europe-west1.run.app/auth/verify?token=${token}`;
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
              <p>Oder kopiere diesen Link in deinen Browser:<br>
                <code style="background-color: #f5f5f5; padding: 10px; border-radius: 4px; display: block; margin: 10px 0; word-break: break-all;">
                  ${verifyUrl}
                </code>
              </p>
              <p style="color: #777; font-size: 14px; margin-top: 30px;">
                <strong>Wichtig:</strong> Dieser Link ist nur 15 Minuten gültig.
              </p>
              <p style="color: #999; font-size: 12px; border-top: 1px solid #eee; padding-top: 20px; margin-top: 30px;">
                Wenn du dich nicht bei Signly registriert hast, ignoriere diese E-Mail bitte.
              </p>
            </div>`,
      headers: {
        'X-Priority': '1',
        'Importance': 'high'
      }
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      this.logger.log(`sendVerificationEmail: mail sent to ${email}, messageId: ${info.messageId}`);
      return info;
    } catch (error) {
      this.logger.error(`sendVerificationEmail ERROR: ${error.message}`, error.stack);
      throw error;
    }
  }
}