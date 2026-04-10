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
  BadRequestException,
  Delete,
  UseInterceptors,
  UploadedFile,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { AppleAppLoginDto } from './dto/apple-app-login.dto';
import type { Response, Request } from 'express';
import * as admin from 'firebase-admin';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { renderSuccessPageHtml, renderExpiredPageHtml } from './templates';
import { UpdateProfileDto } from './update-profile.dto';
import { JwtService } from '@nestjs/jwt';
import { AppleSignInService } from './apple/apple-signin.service';
import {
  UpdateLessonPerformanceDto,
  UpdateTestPerformanceDto,
  UpdateLessonPerformanceMatrixDto,
  UpdateTestPerformanceMatrixDto,
} from './dto/update-performance.dto';
import {
  UpdateDictionaryDto,
  UpdateFavoriteGesturesDto,
  UpdateBadgesDto,
} from './dto/update-collections.dto';
import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import type { AvatarUploadFile } from './auth.service';
import {
  formatLogContext,
  hasValue,
  maskEmail,
  maskIdentifier,
  maskId,
  maskToken,
} from '../common/logging/redaction';

const AVATAR_UPLOAD_MAX_BYTES = Number(process.env.AVATAR_MAX_BYTES ?? 5 * 1024 * 1024);

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly authService: AuthService,
    private readonly appleSignInService: AppleSignInService,
    @Inject('FIREBASE_APP') private firebaseApp: admin.app.App,
    private readonly jwtService: JwtService,
  ) {}

  @Post('signup')
  async signUp(@Body() signupData: SignupDto) {
    this.logger.log(
      'signup called' +
        formatLogContext({
          email: maskEmail((signupData as any)?.email),
          hasPassword: hasValue((signupData as any)?.password),
          nameLength:
            typeof (signupData as any)?.name === 'string'
              ? ((signupData as any).name as string).trim().length
              : undefined,
        }),
    );
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
    this.logger.log(
      'login called' +
        formatLogContext({
          identifier: maskIdentifier((credentials as any)?.identifier),
          hasPassword: hasValue((credentials as any)?.password),
        }),
    );
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
    this.logger.log(
      'refresh called' +
        formatLogContext({
          tokenPresent: hasValue(refreshtokenDto?.refreshToken),
        }),
    );
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
    this.logger.log(
      'VERIFY ENDPOINT CALLED' +
        formatLogContext({
          token: maskToken(token, 'verifyToken'),
          hasNameQuery: hasValue(nameQuery),
        }),
    );

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

      this.logger.log(
        'verify: token still valid, calling authService.verifyEmailToken' +
          formatLogContext({ token: maskToken(token, 'verifyToken') }),
      );
      const result = await this.authService.verifyEmailToken(token);
      this.logger.log(
        'verify: result received' +
          formatLogContext({
            success: result?.success,
            userIdPresent: hasValue(result?.userId),
            email: maskEmail(result?.email),
          }),
      );

      if (!result.success) {
        this.logger.warn(
          `verify: service returned error='${result.error}', rendering expired page`,
        );
        return res.status(400).send(renderExpiredPageHtml());
      }

      const userName = (result.name && result.name.trim()) || fallbackName;
      this.logger.log(
        'verify: rendering success page' +
          formatLogContext({
            userNameLength: userName.length,
          }),
      );
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
    const googleUser = req.user as { email: string; name: string; googleId: string };
    this.logger.log(
      'googleAuthRedirect called' +
        formatLogContext({
          hasUser: !!googleUser,
          email: maskEmail(googleUser?.email),
          googleId: maskId(googleUser?.googleId),
        }),
    );

    const { accessToken, refreshToken, loginStreak, longestLoginStreak } =
      await this.authService.loginWithGoogle(googleUser);

    const appRedirectUrl =
      `signly://auth/google` +
      `?accessToken=${encodeURIComponent(accessToken)}` +
      `&refreshToken=${encodeURIComponent(refreshToken)}` +
      `&loginStreak=${encodeURIComponent(String(loginStreak ?? 0))}` +
      `&longestLoginStreak=${encodeURIComponent(String(longestLoginStreak ?? 0))}`;

    this.logger.log(
      'googleAuthRedirect redirecting to mobile deep link' +
        formatLogContext({
          hasAccessToken: hasValue(accessToken),
          hasRefreshToken: hasValue(refreshToken),
        }),
    );
    return res.redirect(appRedirectUrl);
  }

  // Apple OAuth Start (native app payload via GET link)
  @Get('apple')
  async appleAuth(@Query() query: AppleAppLoginDto, @Res() res: Response) {
    try {
      this.logger.log(
        'appleAuth(GET) called with native payload' +
          formatLogContext({
            hasUser: hasValue(query.user),
            hasEmail: hasValue(query.email),
          }),
      );

      const tokens = await this.handleAppleAppFlow(query, 'web-get');
      const appRedirectUrl = this.buildAppleDeepLink(tokens);

      this.logger.log(
        'appleAuth(GET) redirecting to mobile deep link' +
          formatLogContext({
            hasAccessToken: hasValue(tokens?.accessToken),
            hasRefreshToken: hasValue(tokens?.refreshToken),
          }),
      );
      return res.redirect(appRedirectUrl);
    } catch (err: any) {
      this.logger.error(`appleAuth(GET) ERROR: ${err?.message}`, err?.stack);

      const msg = err instanceof BadRequestException ? 'bad_request' : 'server_error';
      return res.redirect(
        `signly://auth/error?provider=apple&message=${encodeURIComponent(msg)}`,
      );
    }
  }

  /**
   * Native iOS app hands over the raw identityToken instead of going through the web redirect flow.
   */
  @Post('apple/app')
  async appleAuthFromApp(@Body() dto: AppleAppLoginDto) {
    try {
      this.logger.log(
        'appleAuthFromApp called (mobile flow)' +
          formatLogContext({
            hasUser: hasValue(dto.user),
            hasEmail: hasValue(dto.email),
          }),
      );

      return this.handleAppleAppFlow(dto, 'native-post');
    } catch (err: any) {
      this.logger.error(`appleAuthFromApp ERROR: ${err?.message}`, err?.stack);
      throw err;
    }
  }

  private buildAppleDeepLink(tokens: {
    accessToken: string;
    refreshToken: string;
    loginStreak?: number;
    longestLoginStreak?: number;
  }): string {
    return (
      `signly://auth/apple` +
      `?accessToken=${encodeURIComponent(tokens.accessToken)}` +
      `&refreshToken=${encodeURIComponent(tokens.refreshToken)}` +
      `&loginStreak=${encodeURIComponent(String(tokens.loginStreak ?? 0))}` +
      `&longestLoginStreak=${encodeURIComponent(String(tokens.longestLoginStreak ?? 0))}`
    );
  }

  private async handleAppleAppFlow(
    dto: AppleAppLoginDto,
    source: 'web-get' | 'native-post',
  ) {
    const appleUser = await this.appleSignInService.buildProfileFromAppPayload({
      identityToken: dto.identityToken,
      user: dto.user,
      email: dto.email,
      fullName: dto.fullName,
      firstName: dto.firstName,
      lastName: dto.lastName,
    });

    this.logger.log(
      `handleAppleAppFlow resolved appleUser (${source})` +
        formatLogContext({
          email: maskEmail(appleUser.email),
          appleId: maskId(appleUser.appleId),
        }),
    );

    return this.authService.loginWithApple(appleUser);
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
      'updateProfile endpoint called' +
        formatLogContext({
          userId: maskId(userId),
          hasName: hasValue((profileDto as any)?.name),
          aboutMeLength:
            typeof (profileDto as any)?.aboutMe === 'string'
              ? ((profileDto as any).aboutMe as string).trim().length
              : undefined,
        }),
    );

    return this.authService.updateProfile(userId, profileDto);
  }

  @Get('profile/about')
  async getProfileAbout(
    @Query('accessToken') accessTokenQuery: string | undefined,
    @Req() req: Request,
  ) {
    this.logger.log('getProfileAbout called');
    const accessToken = this.resolveAccessToken(req, accessTokenQuery);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.getProfileAbout(userId);
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

  @Get('lessons/performance')
  async getLessonPerformance(
    @Query('accessToken') accessTokenQuery: string | undefined,
    @Req() req: Request,
  ) {
    this.logger.log('getLessonPerformance called');
    const accessToken = this.resolveAccessToken(req, accessTokenQuery);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.getLessonPerformance(userId);
  }

  @Post('lessons/performance')
  async updateLessonPerformance(
    @Body() dto: UpdateLessonPerformanceDto,
    @Req() req: Request,
  ) {
    this.logger.log(
      `updateLessonPerformance called: lessonId=${dto.lessonId}, percentage=${dto.percentage}`,
    );
    const accessToken = this.resolveAccessToken(req, undefined, dto.accessToken);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.updateLessonPerformance(userId, dto.lessonId, dto.percentage);
  }

  @Post('lessons/performance/bulk')
  async setLessonPerformanceMatrix(
    @Body() dto: UpdateLessonPerformanceMatrixDto,
    @Req() req: Request,
  ) {
    this.logger.log(
      `setLessonPerformanceMatrix called with ${dto.entries?.length ?? 0} entries`,
    );
    const accessToken = this.resolveAccessToken(req, undefined, dto.accessToken);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.setLessonPerformanceMatrix(userId, dto.entries ?? []);
  }

  @Get('tests/performance')
  async getTestPerformance(
    @Query('accessToken') accessTokenQuery: string | undefined,
    @Req() req: Request,
  ) {
    this.logger.log('getTestPerformance called');
    const accessToken = this.resolveAccessToken(req, accessTokenQuery);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.getTestPerformance(userId);
  }

  @Post('tests/performance')
  async updateTestPerformance(
    @Body() dto: UpdateTestPerformanceDto,
    @Req() req: Request,
  ) {
    this.logger.log(
      `updateTestPerformance called: testId=${dto.testId}, percentage=${dto.percentage}`,
    );
    const accessToken = this.resolveAccessToken(req, undefined, dto.accessToken);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.updateTestPerformance(userId, dto.testId, dto.percentage);
  }

  @Post('tests/performance/bulk')
  async setTestPerformanceMatrix(
    @Body() dto: UpdateTestPerformanceMatrixDto,
    @Req() req: Request,
  ) {
    this.logger.log(`setTestPerformanceMatrix called with ${dto.entries?.length ?? 0} entries`);
    const accessToken = this.resolveAccessToken(req, undefined, dto.accessToken);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.setTestPerformanceMatrix(userId, dto.entries ?? []);
  }

  @Get('dictionary')
  async getDictionary(
    @Query('accessToken') accessTokenQuery: string | undefined,
    @Req() req: Request,
  ) {
    this.logger.log('getDictionary called');
    const accessToken = this.resolveAccessToken(req, accessTokenQuery);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.getDictionaryEntries(userId);
  }

  @Post('dictionary')
  async updateDictionary(@Body() dto: UpdateDictionaryDto, @Req() req: Request) {
    this.logger.log(
      `updateDictionary called with ${dto.dictionaryEntries?.length ?? 0} entries`,
    );
    const accessToken = this.resolveAccessToken(req, undefined, dto.accessToken);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.updateDictionaryEntries(userId, dto.dictionaryEntries ?? []);
  }

  @Get('favorite-gestures')
  async getFavoriteGestures(
    @Query('accessToken') accessTokenQuery: string | undefined,
    @Req() req: Request,
  ) {
    this.logger.log('getFavoriteGestures called');
    const accessToken = this.resolveAccessToken(req, accessTokenQuery);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.getFavoriteGestures(userId);
  }

  @Post('favorite-gestures')
  async updateFavoriteGestures(
    @Body() dto: UpdateFavoriteGesturesDto,
    @Req() req: Request,
  ) {
    this.logger.log(
      `updateFavoriteGestures called with ${dto.favoriteGestures?.length ?? 0} entries`,
    );
    const accessToken = this.resolveAccessToken(req, undefined, dto.accessToken);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.updateFavoriteGestures(userId, dto.favoriteGestures ?? []);
  }

  @Get('badges')
  async getBadges(
    @Query('accessToken') accessTokenQuery: string | undefined,
    @Req() req: Request,
  ) {
    const accessToken = this.resolveAccessToken(req, accessTokenQuery);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.getBadges(userId);
  }

  @Post('badges')
  async updateBadges(
    @Body() dto: UpdateBadgesDto,
    @Req() req: Request,
  ) {
    const accessToken = this.resolveAccessToken(req, undefined, dto.accessToken);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.updateBadges(userId, dto.badges ?? []);
  }

  @Get('profile/avatar')
  async getAvatar(
    @Query('accessToken') accessTokenQuery: string | undefined,
    @Req() req: Request,
  ) {
    this.logger.log('getAvatar called');
    const accessToken = this.resolveAccessToken(req, accessTokenQuery);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.getAvatar(userId);
  }

  @Post('profile/avatar')
  @UseInterceptors(
    FileInterceptor('avatar', {
      storage: memoryStorage(),
      limits: { fileSize: AVATAR_UPLOAD_MAX_BYTES },
    }),
  )
  async uploadAvatar(
    @UploadedFile() file: AvatarUploadFile,
    @Req() req: Request,
  ) {
    this.logger.log('uploadAvatar called');
    const accessToken = this.resolveAccessToken(req);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.uploadAvatar(userId, file);
  }

  @Delete('profile/avatar')
  async deleteAvatar(
    @Query('accessToken') accessTokenQuery: string | undefined,
    @Req() req: Request,
  ) {
    this.logger.log('deleteAvatar called');
    const accessToken = this.resolveAccessToken(req, accessTokenQuery);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.deleteAvatar(userId);
  }

  @Get('profile/avatar/raw')
  async getAvatarRaw(
    @Query('accessToken') accessTokenQuery: string | undefined,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    this.logger.log('getAvatarRaw called');
    const accessToken = this.resolveAccessToken(req, accessTokenQuery);
    const userId = this.resolveUserIdFromToken(accessToken);
    const { stream, mimeType } = await this.authService.downloadAvatar(userId);
    res.setHeader('Content-Type', mimeType || 'application/octet-stream');
    return stream.pipe(res);
  }

  @Post('friends/request')
  async sendFriendRequest(
    @Body('targetUsername') targetUsername: string,
    @Query('accessToken') accessTokenQuery: string | undefined,
    @Req() req: Request,
  ) {
    this.logger.log('sendFriendRequest called');
    const accessToken = this.resolveAccessToken(req, accessTokenQuery);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.sendFriendRequest(userId, targetUsername);
  }

  @Get('friends/requests')
  async getIncomingFriendRequests(
    @Query('accessToken') accessTokenQuery: string | undefined,
    @Req() req: Request,
  ) {
    this.logger.log('getIncomingFriendRequests called');
    const accessToken = this.resolveAccessToken(req, accessTokenQuery);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.getIncomingFriendRequests(userId);
  }

  @Post('friends/requests/respond')
  async respondToFriendRequest(
    @Body('requestId') requestId: string,
    @Body('accept') accept: boolean,
    @Query('accessToken') accessTokenQuery: string | undefined,
    @Req() req: Request,
  ) {
    this.logger.log('respondToFriendRequest called');
    const accessToken = this.resolveAccessToken(req, accessTokenQuery);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.respondToFriendRequest(userId, requestId, accept);
  }

  @Get('friends')
  async getFriends(
    @Query('accessToken') accessTokenQuery: string | undefined,
    @Req() req: Request,
  ) {
    this.logger.log('getFriends called');
    const accessToken = this.resolveAccessToken(req, accessTokenQuery);
    const userId = this.resolveUserIdFromToken(accessToken);
    return this.authService.getFriends(userId);
  }


  private resolveAccessToken(
    req: Request,
    accessTokenQuery?: string,
    accessTokenBody?: string,
  ): string {
    const authHeader = (req.headers && (req.headers['authorization'] as string)) || '';
    const bearerToken = authHeader?.replace(/^Bearer\s+/i, '') || undefined;
    const token =
      (accessTokenBody && accessTokenBody.trim()) ||
      (accessTokenQuery && accessTokenQuery.trim()) ||
      (bearerToken && bearerToken.trim());

    if (!token) {
      this.logger.warn('resolveAccessToken: missing access token');
      throw new UnauthorizedException('Missing access token');
    }

    return token;
  }

  private resolveUserIdFromToken(accessToken: string): string {
    try {
      const payload = this.jwtService.verify(accessToken);
      const userId = payload?.userId;
      if (!userId) {
        this.logger.warn('resolveUserIdFromToken: token payload has no userId');
        throw new UnauthorizedException('Invalid token payload');
      }
      return userId;
    } catch (err: any) {
      this.logger.warn(`resolveUserIdFromToken: invalid access token: ${err?.message}`);
      throw new UnauthorizedException('Invalid access token');
    }
  }
}
