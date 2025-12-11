import {
  Controller,
  Post,
  Body,
  Logger,
  Get,
  Query,
  Res,
  Inject,
  UseGuards,
  Req,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import type { Response, Request } from 'express';
import * as admin from 'firebase-admin';
import { GoogleAuthGuard } from './guards/google-auth.guard';

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

  // NEU: Google OAuth Start
  @Get('google')
  @UseGuards(GoogleAuthGuard)
  async googleAuth() {
    this.logger.log('googleAuth endpoint called');
    // Redirect zu Google macht der Guard/Passport
    return;
  }

  // NEU: Google OAuth Redirect → Deep-Link in die App
  @Get('google/redirect')
  @UseGuards(GoogleAuthGuard)
  async googleAuthRedirect(@Req() req: Request, @Res() res: Response) {
    this.logger.log(
      `googleAuthRedirect called, user=${JSON.stringify(req.user)}`,
    );

    const googleUser = req.user as {
      email: string;
      name: string;
      googleId: string;
    };

    const { accessToken, refreshToken } =
      await this.authService.loginWithGoogle(googleUser);

    // Deep-Link in deine App – Scheme/Path bei Bedarf anpassen
    const appRedirectUrl =
      `signly://auth/google` +
      `?accessToken=${encodeURIComponent(accessToken)}` +
      `&refreshToken=${encodeURIComponent(refreshToken)}`;

    this.logger.log(`googleAuthRedirect redirecting to ${appRedirectUrl}`);
    return res.redirect(appRedirectUrl);
  }

  // Neu: zentraler, geschützter GLB-Download-Endpunkt
  @Get('glb')
  async getGlb(
    @Query('file') file: string,
    @Query('accessToken') accessTokenQuery: string | undefined,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    this.logger.log(
      `glb download requested file=${file}, tokenProvided=${
        accessTokenQuery ? '[q]' : '[no-q]'
      }`,
    );

    // Basic validation
    if (
      !file ||
      typeof file !== 'string' ||
      !file.toLowerCase().endsWith('.glb')
    ) {
      this.logger.warn('getGlb: invalid or missing file param');
      return res.status(400).json({ error: 'Invalid file parameter' });
    }

    // extract token from query or Authorization header
    const authHeader =
      (req.headers && (req.headers['authorization'] as string)) || '';
    const bearerToken =
      authHeader?.replace(/^Bearer\s+/i, '') || undefined;
    const accessToken =
      (accessTokenQuery && accessTokenQuery.trim()) ||
      (bearerToken && bearerToken.trim());

    if (!accessToken) {
      this.logger.warn('getGlb: missing access token');
      return res.status(401).json({ error: 'Missing access token' });
    }

    try {
      const tokenData = await this.validateGlbToken(accessToken, file);
      // tokenData kann zusätzliche Metadaten enthalten; hier nicht weiter verwendet

      const safeFile = this.sanitizeFilePath(file);
      await this.streamGlbFromStorage(safeFile, res);
      return;
    } catch (err: any) {
      // specific errors already logged/translated inside helper methods
      this.logger.error(`getGlb ERROR: ${err?.message}`);
      if (err instanceof UnauthorizedException)
        return res.status(401).json({ error: err.message });
      if (err instanceof ForbiddenException)
        return res.status(403).json({ error: err.message });
      // default
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  // Validiert Token-Dokument in Firestore
  private async validateGlbToken(
    accessToken: string,
    requestedFile?: string,
  ) {
    const firestore = this.firebaseApp.firestore();
    const tokenDocRef =
      firestore.collection('glbAccessTokens').doc(accessToken);
    const tokenDoc = await tokenDocRef.get();

    if (!tokenDoc.exists) {
      this.logger.warn('validateGlbToken: access token not found');
      throw new UnauthorizedException('Invalid access token');
    }

    const tokenData = tokenDoc.data() as any;
    if (!tokenData) {
      this.logger.warn('validateGlbToken: token doc empty');
      throw new UnauthorizedException('Invalid access token');
    }

    if (tokenData.expiresAt) {
      const expiresAt: Date =
        typeof tokenData.expiresAt.toDate === 'function'
          ? tokenData.expiresAt.toDate()
          : new Date(tokenData.expiresAt);

      if (expiresAt.getTime() < Date.now()) {
        this.logger.log('validateGlbToken: token expired');
        throw new UnauthorizedException('Access token expired');
      }
    }

    if (
      tokenData.allowedFiles &&
      Array.isArray(tokenData.allowedFiles) &&
      requestedFile
    ) {
      // falls nur bestimmte Dateien erlaubt sind
      if (!tokenData.allowedFiles.includes(requestedFile)) {
        this.logger.warn(
          'validateGlbToken: token not allowed for requested file',
        );
        throw new ForbiddenException('Token not allowed for this file');
      }
    }

    return tokenData;
  }

  // Sanitize: entferne führende Slashes und Pfad-Traversal
  private sanitizeFilePath(file: string) {
    return file.replace(/^\/+/, '').replace(/\.\./g, '');
  }

  // Streamt die Datei sicher aus Firebase Storage in die Response
  private async streamGlbFromStorage(safeFile: string, res: Response) {
    const bucket = this.firebaseApp.storage().bucket();
    const remoteFile = bucket.file(safeFile);

    const [exists] = await remoteFile.exists();
    if (!exists) {
      this.logger.warn(
        `streamGlbFromStorage: file not found ${safeFile}`,
      );
      res.status(404).json({ error: 'File not found' });
      return;
    }

    res.setHeader('Content-Type', 'model/gltf-binary');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${safeFile.split('/').pop()}"`,
    );

    const stream = remoteFile.createReadStream();
    stream.on('error', (err) => {
      this.logger.error(
        `streamGlbFromStorage stream error: ${err?.message}`,
        err?.stack,
      );
      if (!res.headersSent) {
        res.status(500).json({ error: 'Error streaming file' });
      } else {
        try {
          res.end();
        } catch (_) {}
      }
    });

    stream.pipe(res);
  }

  private renderSuccessPage(res: Response, name: string) {
    const safeName = (name || '')
      .toString()
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    const baseUrl = 'https://backend.signly.at';
    const assetsBaseUrl = `${baseUrl}/email-assets`;

    const html = `
      <!DOCTYPE html>
      <html lang="de">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
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

          html, body {
            margin: 0;
            padding: 0;
            width: 100%;
            height: 100%;
          }

          body {
            min-height: 100vh;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
            background: radial-gradient(circle at top left, #e0f7ff 0, #f4fbff 45%, #ffffff 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
          }

          .card {
            width: 100%;
            max-width: 520px;
            background: var(--bg-card);
            border-radius: 20px;
            box-shadow: 0 18px 45px rgba(15, 23, 42, 0.18);
            padding: 28px 24px 24px;
            position: relative;
            overflow: hidden;
          }

          .card::before {
            content: "";
            position: absolute;
            inset: 0;
            background: radial-gradient(circle at top right, rgba(166,249,253,0.55), transparent 60%);
            opacity: 0.85;
            pointer-events: none;
          }
          

          #confetti-canvas {
            position: fixed;
            inset: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 999;
          }

          @media (max-width: 520px) {
            body {
              padding: 16px;
            }

            .card {
              padding: 22px 18px 18px;
            }

            .hero {
              flex-direction: column;
              text-align: center;
            }

            .hero-copy {
              text-align: center;
            }

            .card-header {
              flex-direction: row;
            }
          }
        </style>
      </head>
      <body>
        <canvas id="confetti-canvas"></canvas>

        <main class="card" role="main" aria-label="Bestätigung deiner E-Mail-Adresse">
          <div class="card-inner">
            <header class="card-header">
              <div class="logo">
                <img
                  src="${assetsBaseUrl}/Logo.png"
                  alt="Signly Logo"
                  style="height: 36px; width: auto;"
                  loading="eager"
                />
                <span class="brand-name">ignly</span>
              </div>
              <div class="pill">E-Mail bestätigt</div>
            </header>

            <section class="hero">
              <div class="hero-illustration" aria-hidden="true">
                <img
                  src="${assetsBaseUrl}/Maskotchen.png"
                  alt="Signly Maskottchen"
                  style="max-width: 160px; width: 100%; height: auto; display: block;"
                  loading="eager"
                />
              </div>
              <div class="hero-copy">
                <div class="status-icon" aria-hidden="true"></div>
                <h1>E-Mail erfolgreich verifiziert</h1>
                <p class="subtitle">
                  Deine E-Mail-Adresse wurde bestätigt und dein Signly-Account ist jetzt erstellt.
                </p>
                <p class="username">
                  Willkommen bei Signly, ${safeName}!
                </p>
                <p class="hint">
                  Du kannst dieses Fenster jetzt schließen, merke dir nur deine Anmeldedaten.
                </p>
              </div>
            </section>
          </div>
        </main>

        <script>
          (function () {
            const canvas = document.getElementById('confetti-canvas');
            if (!canvas || !canvas.getContext) return;

            const ctx = canvas.getContext('2d');
            let width = window.innerWidth;
            let height = window.innerHeight;
            canvas.width = width;
            canvas.height = height;

            window.addEventListener('resize', () => {
              width = window.innerWidth;
              height = window.innerHeight;
              canvas.width = width;
              canvas.height = height;
            });

            const colors = ['#a6f9fd', '#3b82c4', '#073b4c', '#facc15'];
            const confettiCount = 120;
            const gravity = 0.25;
            const terminalVelocity = 4;
            const drag = 0.02;

            const randomRange = (min, max) => Math.random() * (max - min) + min;

            const confetti = [];
            for (let i = 0; i < confettiCount; i++) {
              confetti.push({
                color: colors[Math.floor(Math.random() * colors.length)],
                dimensions: {
                  x: randomRange(6, 10),
                  y: randomRange(8, 14),
                },
                position: {
                  x: Math.random() * width,
                  y: randomRange(-height, 0),
                },
                rotation: randomRange(0, 2 * Math.PI),
                velocity: {
                  x: randomRange(-2.5, 2.5),
                  y: randomRange(1, 2.5),
                },
                opacity: 1,
                decay: randomRange(0.003, 0.008),
              });
            }

            const duration = 6000;
            const startTime = performance.now();

            const render = (time) => {
              const elapsed = time - startTime;
              ctx.clearRect(0, 0, width, height);

              confetti.forEach((confetto) => {
                if (confetto.opacity <= 0) return;

                confetto.velocity.x -= confetto.velocity.x * drag;
                confetto.velocity.y = Math.min(
                  confetto.velocity.y + gravity,
                  terminalVelocity
                );

                confetto.position.x += confetto.velocity.x;
                confetto.position.y += confetto.velocity.y;

                confetto.opacity -= confetto.decay;

                if (confetto.position.y >= height) {
                  confetto.position.y = height + 20;
                }
                if (confetto.position.x > width) confetto.position.x = 0;
                if (confetto.position.x < 0) confetto.position.x = width;

                confetto.rotation += confetto.velocity.x * 0.02;

                ctx.save();
                ctx.globalAlpha = Math.max(confetto.opacity, 0);
                ctx.translate(confetto.position.x, confetto.position.y);
                ctx.rotate(confetto.rotation);
                ctx.fillStyle = confetto.color;
                ctx.fillRect(
                  -confetto.dimensions.x / 2,
                  -confetto.dimensions.y / 2,
                  confetto.dimensions.x,
                  confetto.dimensions.y
                );
                ctx.restore();
              });

              const allInvisible = confetti.every((c) => c.opacity <= 0);
              if (elapsed < duration && !allInvisible) {
                requestAnimationFrame(render);
              } else {
                ctx.clearRect(0, 0, width, height);
                if (canvas && canvas.parentNode) {
                  canvas.parentNode.removeChild(canvas);
                }
              }
            };

            requestAnimationFrame(render);
          })();
        </script>
      </body>
      </html>
    `;
    return res.send(html);
  }

  private renderExpiredPage(res: Response) {
    const baseUrl = 'https://backend.signly.at';
    const assetsBaseUrl = `${baseUrl}/email-assets`;

    const html = `
      <!DOCTYPE html>
      <html lang="de">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
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

          html, body {
            margin: 0;
            padding: 0;
            width: 100%;
            height: 100%;
          }

          body {
            margin: 0;
            min-height: 100vh;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
            background: radial-gradient(circle at top left, #ffe2e2 0, #fff5f5 45%, #ffffff 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
          }

          .card {
            width: 100%;
            max-width: 520px;
            background: var(--bg-card);
            border-radius: 20px;
            box-shadow: 0 18px 45px rgba(15, 23, 42, 0.18);
            padding: 28px 24px 24px;
            position: relative;
            overflow: hidden;
          }

          .card::before {
            content: "";
            position: absolute;
            inset: 0;
            background: radial-gradient(circle at top right, rgba(239,68,68,0.12), transparent 60%);
            opacity: 0.85;
            pointer-events: none;
          }

          .card-inner {
            position: relative;
            z-index: 1;
          }

          .card-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 12px;
          }

          .logo {
            display: flex;
            align-items: center;
            gap: 2px;
          }

          .logo img {
            display: block;
            height: 36px;
            width: auto;
          }

          .brand-name {
            font-weight: 700;
            letter-spacing: 0.03em;
            font-size: 14px;
            text-transform: uppercase;
            color: var(--text-main);
            margin-top: 10px;
          }

          .pill {
            font-size: 11px;
            padding: 4px 10px;
            border-radius: 999px;
            border: 1px solid rgba(248,113,113,0.5);
            background: rgba(254,242,242,0.9);
            color: #b91c1c;
          }

          .hero {
            display: flex;
            flex-direction: row;
            align-items: center;
            gap: 16px;
            margin-top: 8px;
          }

          .hero-illustration {
            flex: 0 0 160px;
          }

          .hero-illustration img {
            display: block;
            max-width: 160px;
            width: 100%;
            height: auto;
          }

          .hero-copy {
            flex: 1;
            text-align: left;
          }

          .status-icon {
            width: 40px;
            height: 40px;
            border-radius: 999px;
            background: #fee2e2;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 10px;
            border: 1px solid rgba(248,113,113,0.7);
            position: relative;
          }

          .status-icon::before,
          .status-icon::after {
            content: "";
            position: absolute;
            width: 14px;
            height: 2px;
            background: var(--danger);
            border-radius: 999px;
          }

          .status-icon::before {
            transform: rotate(45deg);
          }

          .status-icon::after {
            transform: rotate(-45deg);
          }

          h1 {
            margin: 0 0 6px;
            font-size: 22px;
            color: var(--text-main);
          }

          .subtitle {
            margin: 0 0 10px;
            font-size: 14px;
            color: var(--text-muted);
          }

          .hint {
            color: #9ca3af;
            font-size: 12px;
            margin: 0;
          }

          @media (max-width: 520px) {
            body {
              padding: 16px;
            }

            .card {
              padding: 22px 18px 18px;
            }

            .hero {
              flex-direction: column;
              text-align: center;
            }

            .hero-copy {
              text-align: center;
            }

            .card-header {
              flex-direction: row;
            }
          }
        </style>
      </head>
      <body>
        <main class="card" role="main" aria-label="Hinweis: Bestätigungslink abgelaufen">
          <div class="card-inner">
            <header class="card-header">
              <div class="logo">
                <img
                  src="${assetsBaseUrl}/Logo.png"
                  alt="Signly Logo"
                  style="height: 36px; width: auto;"
                  loading="eager"
                />
                <span class="brand-name">ignly</span>
              </div>
              <div class="pill">Link abgelaufen</div>
            </header>

            <section class="hero">
              <div class="hero-illustration" aria-hidden="true">
                <img
                  src="${assetsBaseUrl}/Maskotchen.png"
                  alt="Signly Maskottchen"
                  style="max-width: 160px; width: 100%; height: auto; display: block;"
                  loading="eager"
                />
              </div>
              <div class="hero-copy">
                <div class="status-icon" aria-hidden="true"></div>
                <h1>Dieser Bestätigungslink ist nicht mehr gültig</h1>
                <p class="subtitle">
                  Der Link ist abgelaufen oder wurde bereits verwendet.
                  Bitte fordere einen neuen Bestätigungslink an, um deine E-Mail-Adresse zu verifizieren.
                </p>
              </div>
            </section>
          </div>
        </main>
      </body>
      </html>
    `;
    return res.status(400).send(html);
  }
}
