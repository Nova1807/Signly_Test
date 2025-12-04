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

      const userRef = firestore.collection('users').where('email', '==', email);
      const snapshot = await userRef.get();
      this.logger.log(`signup: existing users with email=${email}: ${snapshot.size}`);

      if (!snapshot.empty) {
        this.logger.warn(`signup: email already in use: ${email}`);
        throw new BadRequestException('Diese Email hat bereits einen Account');
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      this.logger.log('signup: password hashed');

      await firestore.collection('users').add({
        name,
        email,
        password: hashedPassword,
      });

      this.logger.log('signup: user document created');
      return { success: true };
    } catch (err) {
      this.logger.error(`signup internal error: ${err?.message}`, err?.stack);
      throw err;
    }
  }

  async login(credentials: LoginDto) {
    this.logger.log(`login start: ${JSON.stringify(credentials)}`);

    const { email, password } = credentials;

    try {
      const firestore = this.firebaseApp.firestore();
      this.logger.log('login: got firestore instance');

      const userRef = firestore.collection('users').where('email', '==', email);
      const snapshot = await userRef.get();
      this.logger.log(`login: users found with email=${email}: ${snapshot.size}`);

      if (snapshot.empty) {
        this.logger.warn(`login: no user found for email=${email}`);
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
        this.logger.warn(`login: wrong password for email=${email}`);
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

    await firestore.collection('refreshTokens').add({ token, userId, expiryDate });
    this.logger.log('storeRefreshToken: refresh token document created');
  }
}
