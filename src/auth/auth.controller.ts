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
import type { Response } from 'express'; // 👈 'import type' verwenden

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
      return res.status(400).send(`
        <html>
          <head><title>Fehler - Signly</title></head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: red;">❌ Fehler</h1>
            <p>Kein Verifizierungstoken gefunden.</p>
            <p><a href="/">Zur Startseite</a></p>
          </body>
        </html>
      `);
    }
    
    try {
      this.logger.log(`verify: calling authService.verifyEmailToken('${token}')`);
      const result = await this.authService.verifyEmailToken(token);
      
      this.logger.log(`verify: SUCCESS - ${JSON.stringify(result)}`);
      
      // Erfolgreiche HTML Response
      return res.send(`
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
            }
            .login-btn:hover {
              background-color: #45a049;
            }
            .info {
              background-color: #f0f8ff;
              padding: 15px;
              border-radius: 5px;
              margin-top: 30px;
              font-size: 14px;
              color: #555;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="success-icon">✅</div>
            <h1>Email erfolgreich verifiziert!</h1>
            <p>Dein Account wurde aktiviert und ist jetzt bereit zur Nutzung.</p>
            <p>Du kannst dich jetzt mit deinen Zugangsdaten einloggen.</p>
            
            <a href="/login" class="login-btn">Zum Login</a>
            
            <div class="info">
              <p><strong>Deine Registrierung ist abgeschlossen.</strong></p>
              <p>Du wirst in Kürze weitergeleitet...</p>
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
      `);
      
    } catch (err) {
      this.logger.error(`verify ERROR: ${err?.message}`, err?.stack);
      
      // Fehler HTML Response
      let errorMessage = 'Ungültiger oder abgelaufener Verifizierungslink.';
      let errorTitle = 'Verifizierung fehlgeschlagen';
      
      if (err.message?.includes('abgelaufen')) {
        errorMessage = 'Der Verifizierungslink ist abgelaufen (gültig für 15 Minuten). Bitte registriere dich erneut.';
        errorTitle = 'Link abgelaufen';
      } else if (err.message?.includes('bereits registriert')) {
        errorMessage = 'Diese Email ist bereits registriert. Du kannst dich mit deinen Zugangsdaten einloggen.';
        errorTitle = 'Email bereits registriert';
      }
      
      return res.status(400).send(`
        <!DOCTYPE html>
        <html lang="de">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>${errorTitle} - Signly</title>
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
            p {
              color: #666;
              margin-bottom: 30px;
              font-size: 18px;
            }
            .btn {
              display: inline-block;
              padding: 10px 20px;
              text-decoration: none;
              border-radius: 5px;
              font-size: 16px;
              margin: 5px;
            }
            .primary-btn {
              background-color: #f44336;
              color: white;
            }
            .secondary-btn {
              background-color: #e0e0e0;
              color: #333;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="error-icon">❌</div>
            <h1>${errorTitle}</h1>
            <p>${errorMessage}</p>
            
            <a href="/signup" class="btn primary-btn">Erneut registrieren</a>
            <a href="/login" class="btn secondary-btn">Zum Login</a>
          </div>
        </body>
        </html>
      `);
    }
  }
}