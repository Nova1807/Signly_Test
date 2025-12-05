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
  async verify(@Query('token') token: string, @Res() res: Response) {
    this.logger.log(`VERIFY ENDPOINT CALLED with token: ${token}`);

    if (!token || token.trim() === '') {
      this.logger.warn('verify: empty token provided');
      return this.renderSuccessPage(res, '', 'Account');
    }

    try {
      this.logger.log(
        `verify: calling authService.verifyEmailToken('${token}')`,
      );
      const result = await this.authService.verifyEmailToken(token);

      this.logger.log(`verify: result: ${JSON.stringify(result)}`);

      return this.renderSuccessPage(
        res,
        result.email || '',
        result.name || 'Nutzer',
      );
    } catch (err) {
      this.logger.error(`verify ERROR: ${err?.message}`, err?.stack);
      return this.renderSuccessPage(res, '', 'Account');
    }
  }

  private renderSuccessPage(res: Response, email: string, name: string) {
    const html = `
      <!DOCTYPE html>
      <html lang="de">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email verifiziert - Signly</title>
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
            margin-bottom: 20px;
          }
          p {
            color: #666;
            margin-bottom: 30px;
            font-size: 18px;
            line-height: 1.6;
          }
          .user-info {
            background-color: #f0f8ff;
            padding: 20px;
            border-radius: 5px;
            margin: 30px 0;
            text-align: left;
          }
          .user-info p {
            margin: 10px 0;
            color: #333;
            font-size: 16px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="success-icon">✅</div>
          <h1>Account erfolgreich erstellt!</h1>
          
          <div class="user-info">
            <p><strong>Name:</strong> ${name}</p>
            <p><strong>Email:</strong> ${email}</p>
          </div>
          
          <p>Dein Account wurde erfolgreich erstellt und ist bereit zur Nutzung.</p>
        </div>
      </body>
      </html>
    `;
    return res.send(html);
  }
}
