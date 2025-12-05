import {
  Controller,
  Post,
  Body,
  Logger,
  Get,
  Query,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import type { Response } from 'express';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

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

    if ((!token || token.trim() === '') && !decodedName) {
      this.logger.warn('verify: empty token and empty name provided');
      return this.renderSuccessPage(res, 'Nutzer');
    }

    try {
      if (token && token.trim() !== '') {
        this.logger.log(
          `verify: calling authService.verifyEmailToken('${token}')`,
        );

        const result = await this.authService.verifyEmailToken(token);
        this.logger.log(`verify: result: ${JSON.stringify(result)}`);

        // Token ungültig / abgelaufen -> Fehlerseite
        if (
          result.error === 'TOKEN_EXPIRED' ||
          result.error === 'INVALID_TOKEN' ||
          result.error === 'INVALID_TOKEN_DATA' ||
          result.error === 'INVALID_TOKEN_FORMAT'
        ) {
          this.logger.log(
            `verify: token invalid/expired with error='${result.error}', rendering expired page`,
          );
          return this.renderExpiredPage(res);
        }

        // Erfolg: normale Success-Seite mit Name aus Query-Param
        const userName = fallbackName;
        this.logger.log(
          `verify: rendering success page with userName='${userName}'`,
        );
        return this.renderSuccessPage(res, userName);
      }

      if (decodedName) {
        this.logger.log(
          `verify: no token, using decodedName from query: '${decodedName}'`,
        );
        return this.renderSuccessPage(res, decodedName);
      }

      return this.renderSuccessPage(res, 'Nutzer');
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
        <title>Account erstellt - Signly</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background-color: #f5f5f5;
            margin: 0;
          }
          .container {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          }
          .success-icon {
            font-size: 60px;
            color: #4CAF50;
            margin-bottom: 20px;
          }
          h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
          }
          .username {
            color: #4CAF50;
            font-size: 24px;
            font-weight: bold;
            margin: 20px 0;
          }
          .subtitle {
            color: #666;
            font-size: 16px;
            margin-bottom: 30px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="success-icon">✅</div>
          <h1>Account erfolgreich erstellt</h1>
          <p class="subtitle">Willkommen bei Signly</p>
          <div class="username">${safeName}</div>
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
          body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background-color: #f5f5f5;
            margin: 0;
          }
          .container {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          }
          .error-icon {
            font-size: 60px;
            color: #e53935;
            margin-bottom: 20px;
          }
          h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
          }
          .subtitle {
            color: #666;
            font-size: 16px;
            margin-bottom: 30px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="error-icon">⚠️</div>
          <h1>Link ist nicht mehr gültig</h1>
          <p class="subtitle">
            Der Bestätigungslink ist abgelaufen oder ungültig.<br/>
            Bitte fordere einen neuen Bestätigungslink an.
          </p>
        </div>
      </body>
      </html>
    `;
    return res.status(400).send(html);
  }
}
