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
    this.logger.log(`refresh called with body: ${JSON.stringify(refreshtokenDto)}`);
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
      return this.renderErrorPage(res, 'KEIN_TOKEN', 'Kein Verifizierungstoken gefunden.');
    }
    
    try {
      this.logger.log(`verify: calling authService.verifyEmailToken('${token}')`);
      const result = await this.authService.verifyEmailToken(token);
      
      this.logger.log(`verify: result: ${JSON.stringify(result)}`);
      
      if (result.success) {
        // ERFOLG: Account wurde erstellt
        return this.renderSuccessPage(res, result.email || '', result.name || '');
      } else {
        // FEHLER: Zeige entsprechende Fehlerseite
        return this.renderErrorPage(res, result.error || 'UNKNOWN_ERROR', result.message, result.email);
      }
      
    } catch (err) {
      this.logger.error(`verify ERROR: ${err?.message}`, err?.stack);
      return this.renderErrorPage(res, 'UNKNOWN_ERROR', 'Unbekannter Fehler aufgetreten.');
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
          .login-btn {
            display: inline-block;
            background-color: #4CAF50;
            color: white;
            padding: 15px 30px;
            text-decoration: none;
            border-radius: 5px;
            font-size: 18px;
            font-weight: bold;
            transition: background-color 0.3s;
            margin-top: 20px;
          }
          .login-btn:hover {
            background-color: #45a049;
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
          }
          .info-text {
            font-size: 14px;
            color: #777;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="success-icon">✅</div>
          <h1>Email erfolgreich verifiziert!</h1>
          
          <div class="user-info">
            <p><strong>Ihr Account wurde erfolgreich erstellt:</strong></p>
            <p><strong>Name:</strong> ${name}</p>
            <p><strong>Email:</strong> ${email}</p>
          </div>
          
          <p>Ihr Account wurde aktiviert und ist jetzt bereit zur Nutzung.</p>
          <p>Sie können sich jetzt mit Ihren Zugangsdaten einloggen.</p>
          
          <a href="/login" class="login-btn">Zum Login</a>
          
          <div class="info-text">
            <p>Sie werden in 5 Sekunden automatisch zum Login weitergeleitet...</p>
          </div>
        </div>
        
        <script>
          // Automatische Weiterleitung nach 5 Sekunden
          setTimeout(function() {
            window.location.href = '/login';
          }, 5000);
        </script>
      </body>
      </html>
    `;
    
    return res.send(html);
  }

  private renderErrorPage(res: Response, errorCode: string, errorMessage: string, email?: string) {
    let title = 'Verifizierung fehlgeschlagen';
    let details = errorMessage;
    let showLoginButton = true;
    let showRegisterButton = true;
    
    switch(errorCode) {
      case 'TOKEN_EXPIRED':
        title = 'Link abgelaufen';
        details = 'Der Verifizierungslink ist abgelaufen (gültig für 15 Minuten).';
        showLoginButton = false;
        break;
      case 'EMAIL_ALREADY_REGISTERED':
        title = 'Email bereits registriert';
        details = email ? 
          `Die Email <strong>${email}</strong> ist bereits registriert.` : 
          'Diese Email ist bereits registriert.';
        details += ' Sie können sich mit Ihren Zugangsdaten einloggen.';
        showRegisterButton = false;
        break;
      case 'INVALID_TOKEN':
      case 'INVALID_TOKEN_DATA':
      case 'INVALID_TOKEN_FORMAT':
        title = 'Ungültiger Link';
        details = 'Der Verifizierungslink ist ungültig oder wurde bereits verwendet.';
        break;
      case 'MISSING_FIELDS':
        title = 'Fehlerhafte Daten';
        details = 'Die Benutzerdaten im Verifizierungslink sind unvollständig.';
        break;
      case 'SERVER_ERROR':
        title = 'Server Fehler';
        details = 'Ein Serverfehler ist aufgetreten. Bitte versuchen Sie es später erneut.';
        break;
      case 'KEIN_TOKEN':
        title = 'Kein Token';
        details = 'Es wurde kein Verifizierungstoken gefunden.';
        break;
    }
    
    const html = `
      <!DOCTYPE html>
      <html lang="de">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${title} - Signly</title>
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
            color: #f44336;
            margin-bottom: 20px;
          }
          h1 {
            color: #333;
            margin-bottom: 20px;
          }
          .error-message {
            color: #666;
            margin-bottom: 30px;
            font-size: 18px;
            line-height: 1.6;
            background-color: #fff5f5;
            padding: 20px;
            border-radius: 5px;
            border-left: 4px solid #f44336;
          }
          .btn-container {
            margin-top: 30px;
          }
          .btn {
            display: inline-block;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: bold;
            margin: 10px;
            transition: opacity 0.3s;
          }
          .btn:hover {
            opacity: 0.9;
          }
          .primary-btn {
            background-color: #f44336;
            color: white;
          }
          .secondary-btn {
            background-color: #2196F3;
            color: white;
          }
          .tertiary-btn {
            background-color: #e0e0e0;
            color: #333;
          }
          .info-text {
            font-size: 14px;
            color: #777;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="error-icon">❌</div>
          <h1>${title}</h1>
          
          <div class="error-message">
            ${details}
          </div>
          
          <div class="btn-container">
            ${showLoginButton ? '<a href="/login" class="btn secondary-btn">Zum Login</a>' : ''}
            ${showRegisterButton ? '<a href="/signup" class="btn primary-btn">Erneut registrieren</a>' : ''}
            <a href="/" class="btn tertiary-btn">Zur Startseite</a>
          </div>
          
          <div class="info-text">
            <p>Bei weiteren Fragen wenden Sie sich bitte an den Support.</p>
          </div>
        </div>
      </body>
      </html>
    `;
    
    return res.status(400).send(html);
  }
}