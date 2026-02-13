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
  BadRequestException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import type { Response, Request } from 'express';
import * as admin from 'firebase-admin';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { GlbService } from './glb.service';
import { renderSuccessPageHtml, renderExpiredPageHtml } from './templates';
import { UpdateProfileDto } from './update-profile.dto';
import { JwtService } from '@nestjs/jwt';
import { AppleSignInService } from './apple/apple-signin.service';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly authService: AuthService,
    private readonly appleSignInService: AppleSignInService,
    @Inject('FIREBASE_APP') private firebaseApp: admin.app.App,
    private readonly glbService: GlbService,
    private readonly jwtService: JwtService,
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
      this.logger.log(
        `login finished successfully (streak=${result.loginStreak}, longest=${result.longestLoginStreak})`,
      );
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
      const result = await this.authService.refreshTokens(refreshtokenDto.refreshToken);
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
    this.logger.log(`VERIFY ENDPOINT CALLED with token: ${token}, nameQuery: ${nameQuery}`);

    const fallbackName = 'Nutzer';

    if (!token || token.trim() === '') {
      this.logger.warn('verify: empty token provided');
      return res.status(400).send(renderExpiredPageHtml());
    }

    try {
      const firestore = this.firebaseApp.firestore();

      const docRef = firestore.collection('emailVerifications').doc(token);
      const doc = await docRef.get();

      if (!doc.exists) {
        this.logger.warn('verify: emailVerifications doc not found');
        return res.status(400).send(renderExpiredPageHtml());
      }

      const data = doc.data() as any;
      if (!data || !data.expiresAt) {
        this.logger.warn('verify: emailVerifications doc has no expiresAt');
        return res.status(400).send(renderExpiredPageHtml());
      }

      const expiresAt: Date =
        typeof data.expiresAt.toDate === 'function' ? data.expiresAt.toDate() : new Date(data.expiresAt);

      const now = new Date();
      this.logger.log(`verify: expiresAt=${expiresAt.toISOString()}, now=${now.toISOString()}`);

      if (expiresAt.getTime() < now.getTime()) {
        this.logger.log('verify: token expired (controller check)');
        return res.status(400).send(renderExpiredPageHtml());
      }

      this.logger.log(`verify: token still valid, calling authService.verifyEmailToken('${token}')`);
      const result = await this.authService.verifyEmailToken(token);
      this.logger.log(`verify: result: ${JSON.stringify(result)}`);

      if (!result.success) {
        this.logger.warn(
          `verify: service returned error='${result.error}', rendering expired page`,
        );
        return res.status(400).send(renderExpiredPageHtml());
      }

      const userName = (result.name && result.name.trim()) || fallbackName;
      this.logger.log(`verify: rendering success page with userName='${userName}'`);
      return res.send(renderSuccessPageHtml(userName));
    } catch (err) {
      this.logger.error(`verify ERROR: ${err?.message}`, err?.stack);
      return res.status(400).send(renderExpiredPageHtml());
    }
  }

  // Google OAuth Start
  @Get('google')
  @UseGuards(GoogleAuthGuard)
  async googleAuth() {
    this.logger.log('googleAuth endpoint called');
    return;
  }

  // Google OAuth Redirect → Deep-Link in die App
  @Get('google/redirect')
  @UseGuards(GoogleAuthGuard)
  async googleAuthRedirect(@Req() req: Request, @Res() res: Response) {
    this.logger.log(`googleAuthRedirect called, user=${JSON.stringify(req.user)}`);

    const googleUser = req.user as { email: string; name: string; googleId: string };

    const { accessToken, refreshToken, loginStreak, longestLoginStreak } =
      await this.authService.loginWithGoogle(googleUser);

    const appRedirectUrl =
      `signly://auth/google` +
      `?accessToken=${encodeURIComponent(accessToken)}` +
      `&refreshToken=${encodeURIComponent(refreshToken)}` +
      `&loginStreak=${encodeURIComponent(String(loginStreak ?? 0))}` +
      `&longestLoginStreak=${encodeURIComponent(String(longestLoginStreak ?? 0))}`;

    this.logger.log(`googleAuthRedirect redirecting to ${appRedirectUrl}`);
    return res.redirect(appRedirectUrl);
  }

  // Apple OAuth Start
  @Get('apple')
  async appleAuth(@Res() res: Response) {
    this.logger.log('appleAuth endpoint called – redirecting to Apple');
    const authorizeUrl = this.appleSignInService.getAuthorizationUrl();
    return res.redirect(authorizeUrl);
  }

  /**
   * Apple OAuth Redirect (POST)
   * Apple sendet bei "web flow" häufig POST (form-urlencoded) an callbackURL. [page:1]
   */
  @Post('apple/redirect')
  async appleAuthRedirect(@Req() req: Request, @Res() res: Response) {
    try {
      this.logger.log(
        `appleAuthRedirect(POST) called, bodyKeys=${Object.keys(req.body || {}).join(',')}`,
      );

      const payload = this.appleSignInService.extractCallbackPayload(req);
      const appleUser = await this.appleSignInService.buildProfileFromPayload(payload);

      const { accessToken, refreshToken, loginStreak, longestLoginStreak } =
        await this.authService.loginWithApple(appleUser);

      const appRedirectUrl =
        `signly://auth/apple` +
        `?accessToken=${encodeURIComponent(accessToken)}` +
        `&refreshToken=${encodeURIComponent(refreshToken)}` +
        `&loginStreak=${encodeURIComponent(String(loginStreak ?? 0))}` +
        `&longestLoginStreak=${encodeURIComponent(String(longestLoginStreak ?? 0))}`;

      this.logger.log(`appleAuthRedirect redirecting to ${appRedirectUrl}`);
      return res.redirect(appRedirectUrl);
    } catch (err: any) {
      // Damit du endlich siehst was es ist (und nicht nur "Internal server error")
      this.logger.error(`appleAuthRedirect ERROR: ${err?.message}`, err?.stack);

      // Wenn du die Message in die App reichen willst:
      const msg =
        err instanceof BadRequestException
          ? 'bad_request'
          : 'server_error';

      return res.redirect(`signly://auth/error?provider=apple&message=${encodeURIComponent(msg)}`);
    }
  }

  /**
   * Optionaler GET-Fallback (z.B. wenn irgendwo GET statt POST kommt)
   * Wichtig: NICHT die POST-Methode aufrufen, sondern getrennt laufen lassen.
   */
  @Get('apple/redirect')
  async appleAuthRedirectGet(@Req() req: Request, @Res() res: Response) {
    // gleiche Logik wie POST (kopiert, bewusst kein gegenseitiges aufrufen)
    try {
      this.logger.log(
        `appleAuthRedirect(GET) called, queryKeys=${Object.keys(req.query || {}).join(',')}`,
      );

      const payload = this.appleSignInService.extractCallbackPayload(req);
      const appleUser = await this.appleSignInService.buildProfileFromPayload(payload);

      const { accessToken, refreshToken, loginStreak, longestLoginStreak } =
        await this.authService.loginWithApple(appleUser);

      const appRedirectUrl =
        `signly://auth/apple` +
        `?accessToken=${encodeURIComponent(accessToken)}` +
        `&refreshToken=${encodeURIComponent(refreshToken)}` +
        `&loginStreak=${encodeURIComponent(String(loginStreak ?? 0))}` +
        `&longestLoginStreak=${encodeURIComponent(String(longestLoginStreak ?? 0))}`;

      this.logger.log(`appleAuthRedirectGet redirecting to ${appRedirectUrl}`);
      return res.redirect(appRedirectUrl);
    } catch (err: any) {
      this.logger.error(`appleAuthRedirectGet ERROR: ${err?.message}`, err?.stack);
      return res.redirect(`signly://auth/error?provider=apple&message=${encodeURIComponent('server_error')}`);
    }
  }

  // Profil-Update: alles im Body (accessToken + name + aboutMe)
  @Post('profile')
  async updateProfile(@Body() dto: UpdateProfileDto) {
    const accessToken = dto.accessToken;

    if (!accessToken) {
      this.logger.warn('updateProfile: missing access token in body');
      throw new UnauthorizedException('Missing access token');
    }

    let payload: any;
    try {
      payload = this.jwtService.verify(accessToken); // enthält userId
    } catch (e: any) {
      this.logger.warn(`updateProfile: invalid access token: ${e?.message}`);
      throw new UnauthorizedException('Invalid access token');
    }

    const userId = payload.userId;
    if (!userId) {
      this.logger.warn('updateProfile: token has no userId');
      throw new UnauthorizedException('Invalid token payload');
    }

    // accessToken nicht an den Service weiterreichen / nicht speichern
    const { accessToken: _ignored, ...profileDto } = dto;

    this.logger.log(
      `updateProfile endpoint called by userId=${userId} with body=${JSON.stringify(profileDto)}`,
    );

    return this.authService.updateProfile(userId, profileDto);
  }

  // GET current login streaks for the authenticated user
  @Get('streak')
  async getStreak(
    @Query('accessToken') accessTokenQuery: string | undefined,
    @Req() req: Request,
  ) {
    this.logger.log(`getStreak called, tokenProvided=${accessTokenQuery ? '[q]' : '[no-q]'}`);

    const authHeader = (req.headers && (req.headers['authorization'] as string)) || '';
    const bearerToken = authHeader?.replace(/^Bearer\s+/i, '') || undefined;
    const accessToken =
      (accessTokenQuery && accessTokenQuery.trim()) || (bearerToken && bearerToken.trim());

    if (!accessToken) {
      this.logger.warn('getStreak: missing access token');
      throw new UnauthorizedException('Missing access token');
    }

    let payload: any;
    try {
      payload = this.jwtService.verify(accessToken);
    } catch (e: any) {
      this.logger.warn(`getStreak: invalid access token: ${e?.message}`);
      throw new UnauthorizedException('Invalid access token');
    }

    const userId = payload.userId;
    if (!userId) {
      this.logger.warn('getStreak: token has no userId');
      throw new UnauthorizedException('Invalid token payload');
    }

    return this.authService.getStreak(userId);
  }

  // zentraler, geschützter GLB-Download-Endpunkt
  @Get('glb')
  async getGlb(
    @Query('file') file: string,
    @Query('accessToken') accessTokenQuery: string | undefined,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    this.logger.log(
      `glb download requested file=${file}, tokenProvided=${accessTokenQuery ? '[q]' : '[no-q]'}`,
    );

    // Basic validation
    if (!file || typeof file !== 'string' || !file.toLowerCase().endsWith('.glb')) {
      this.logger.warn('getGlb: invalid or missing file param');
      return res.status(400).json({ error: 'Invalid file parameter' });
    }

    // extract token from query or Authorization header
    const authHeader = (req.headers && (req.headers['authorization'] as string)) || '';
    const bearerToken = authHeader?.replace(/^Bearer\s+/i, '') || undefined;
    const accessToken =
      (accessTokenQuery && accessTokenQuery.trim()) || (bearerToken && bearerToken.trim());

    if (!accessToken) {
      this.logger.warn('getGlb: missing access token');
      return res.status(401).json({ error: 'Missing access token' });
    }

    try {
      await this.glbService.validateGlbToken(accessToken, file);

      const safeFile = this.glbService.sanitizeFilePath(file);
      await this.glbService.streamGlbFromStorage(safeFile, res);
      return;
    } catch (err: any) {
      this.logger.error(`getGlb ERROR: ${err?.message}`);
      if (err instanceof UnauthorizedException) return res.status(401).json({ error: err.message });
      if (err instanceof ForbiddenException) return res.status(403).json({ error: err.message });
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
}
