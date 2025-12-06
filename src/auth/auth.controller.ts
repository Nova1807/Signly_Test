import {
  Controller,
  Post,
  Body,
  Logger,
  Get,
  Query,
  Res,
  Inject,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import type { Response } from 'express';
import * as admin from 'firebase-admin';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly authService: AuthService,
    @Inject('FIREBASE_APP') private firebaseApp: admin.app.App,
  ) {}

  @Post('signup')
  async signUp(@Body() signupData: SignupDto) {
    this.logger.log(`signup called with body: ${JSON.stringify(signupData)}`);
    try {
      const result = await this.authService.signup(signupData);
      this.logger.log('signup finished successfully');
      return result;
    } catch (err) {
      this.logger.error(`signup error: ${err?.message}`, err?.stack);
      throw err;
    }
  }

  @Post('login')
  async login(@Body() credentials: LoginDto) {
    this.logger.log(`login called with body: ${JSON.stringify(credentials)}`);
    try {
      const result = await this.authService.login(credentials);
      this.logger.log('login finished successfully');
      return result;
    } catch (err) {
      this.logger.error(`login error: ${err?.message}`, err?.stack);
      throw err;
    }
  }

  @Post('refresh')
  async refreshtoken(@Body() refreshtokenDto: RefreshTokenDto) {
    this.logger.log(
      `refresh called with body: ${JSON.stringify(refreshtokenDto)}`,
    );
    try {
      const result = await this.authService.refreshTokens(
        refreshtokenDto.refreshToken,
      );
      this.logger.log('refresh finished successfully');
      return result;
    } catch (err) {
      this.logger.error(`refresh error: ${err?.message}`, err?.stack);
      throw err;
    }
  }

  @Get('verify')
  async verify(
    @Query('token') token: string,
    @Query('name') nameQuery: string | undefined,
    @Res() res: Response,
  ) {
    this.logger.log(
      `VERIFY ENDPOINT CALLED with token: ${token}, nameQuery: ${nameQuery}`,
    );

    const decodedName = nameQuery ? decodeURIComponent(nameQuery).trim() : '';
    const fallbackName = decodedName || 'Nutzer';

    if (!token || token.trim() === '') {
      this.logger.warn('verify: empty token provided');
      return this.renderExpiredPage(res);
    }

    try {
      const firestore = this.firebaseApp.firestore();

      const docRef = firestore.collection('emailVerifications').doc(token);
      const doc = await docRef.get();

      if (!doc.exists) {
        this.logger.warn('verify: emailVerifications doc not found');
        return this.renderExpiredPage(res);
      }

      const data = doc.data() as any;
      if (!data || !data.expiresAt) {
        this.logger.warn('verify: emailVerifications doc has no expiresAt');
        return this.renderExpiredPage(res);
      }

      const expiresAt: Date =
        typeof data.expiresAt.toDate === 'function'
          ? data.expiresAt.toDate()
          : new Date(data.expiresAt);

      const now = new Date();
      this.logger.log(
        `verify: expiresAt=${expiresAt.toISOString()}, now=${now.toISOString()}`,
      );

      if (expiresAt.getTime() < now.getTime()) {
        this.logger.log('verify: token expired (controller check)');
        return this.renderExpiredPage(res);
      }

      this.logger.log(
        `verify: token still valid, calling authService.verifyEmailToken('${token}')`,
      );
      const result = await this.authService.verifyEmailToken(token);
      this.logger.log(`verify: result: ${JSON.stringify(result)}`);

      if (!result.success) {
        this.logger.warn(
          `verify: service returned error='${result.error}', rendering expired page`,
        );
        return this.renderExpiredPage(res);
      }

      const userName = fallbackName;
      this.logger.log(
        `verify: rendering success page with userName='${userName}'`,
      );
      return this.renderSuccessPage(res, userName);
    } catch (err) {
      this.logger.error(`verify ERROR: ${err?.message}`, err?.stack);
      return this.renderExpiredPage(res);
    }
  }

  private renderSuccessPage(res: Response, name: string) {
    const safeName = (name || '')
      .toString()
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    const html = `
      <!DOCTYPE html>
      <html lang="de">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>E-Mail verifiziert - Signly</title>
        <style>
          :root {
            --bg-page: #f4fbff;
            --bg-card: #ffffff;
            --primary: #073b4c;
            --accent: #a6f9fd;
            --accent-border: #3b82c4;
            --text-main: #0b2135;
            --text-muted: #4a5568;
          }

          * {
            box-sizing: border-box;
          }

          body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 40px 16px;
            background-color: var(--bg-page);
            margin: 0;
          }

          .container {
            max-width: 480px;
            margin: 0 auto;
            background: var(--bg-card);
            padding: 32px 24px 28px;
            border-radius: 16px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.06);
          }

          .icon {
            font-size: 52px;
            margin-bottom: 16px;
          }

          h1 {
            color: var(--primary);
            margin: 0 0 8px;
            font-size: 24px;
          }

          .subtitle {
            color: var(--text-muted);
            font-size: 14px;
            margin: 0 0 20px;
          }

          .username {
            color: var(--text-main);
            font-size: 18px;
            font-weight: bold;
            margin: 8px 0 20px;
          }

          .hint {
            color: var(--text-muted);
            font-size: 13px;
            margin: 0 0 4px;
          }

          .secondary {
            color: #a0aec0;
            font-size: 12px;
            margin: 12px 0 0;
          }

          @media (min-width: 600px) {
            body {
              padding: 60px 16px;
            }
            .container {
              padding: 40px 32px 32px;
            }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="icon">✅</div>
          <h1>E-Mail erfolgreich verifiziert</h1>
          <p class="subtitle">Dein Signly-Account wurde erstellt.</p>
          <div class="username">Willkommen bei Signly, ${safeName}!</div>
          <p class="hint">
            Du kannst dieses Fenster jetzt schließen und deine Zugangsdaten sicher aufbewahren.
          </p>
          <p class="secondary">
            Wenn du diese Registrierung nicht selbst ausgelöst hast, kannst du diese Nachricht ignorieren.
          </p>
        </div>
      </body>
      </html>
    `;
    return res.send(html);
  }

  private renderExpiredPage(res: Response) {
    const html = `
      <!DOCTYPE html>
      <html lang="de">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Link abgelaufen - Signly</title>
        <style>
          :root {
            --bg-page: #fff5f5;
            --bg-card: #ffffff;
            --danger: #e53935;
            --text-main: #1f2933;
            --text-muted: #4a5568;
          }

          * {
            box-sizing: border-box;
          }

          body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 40px 16px;
            background-color: var(--bg-page);
            margin: 0;
          }

          .container {
            max-width: 480px;
            margin: 0 auto;
            background: var(--bg-card);
            padding: 32px 24px 28px;
            border-radius: 16px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.06);
          }

          .error-icon {
            font-size: 52px;
            color: var(--danger);
            margin-bottom: 16px;
          }

          h1 {
            color: var(--text-main);
            margin: 0 0 8px;
            font-size: 24px;
          }

          .subtitle {
            color: var(--text-muted);
            font-size: 14px;
            margin: 0 16px 16px;
          }

          .hint {
            color: #a0aec0;
            font-size: 12px;
            margin: 0;
          }

          @media (min-width: 600px) {
            body {
              padding: 60px 16px;
            }
            .container {
              padding: 40px 32px 32px;
            }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="error-icon">⚠️</div>
          <h1>Link ist nicht mehr gültig</h1>
          <p class="subtitle">
            Der Bestätigungslink ist abgelaufen oder ungültig.<br/>
            Bitte fordere einen neuen Bestätigungslink an, um deine E-Mail-Adresse zu verifizieren.
          </p>
          <p class="hint">
            Wenn du diese Anfrage nicht kennst, kannst du diese Nachricht ignorieren.
          </p>
        </div>
      </body>
      </html>
    `;
    return res.status(400).send(html);
  }
}
