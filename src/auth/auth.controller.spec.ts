import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AppleSignInService } from './apple/apple-signin.service';
import { MailerService } from './mailer.service';
import { ImageModerationService } from './image-moderation.service';

describe('AuthController', () => {
  let controller: AuthController;

  const firebaseAppMock = {
    firestore: () => ({}),
    storage: () => ({ bucket: () => ({}) }),
  };

  const jwtServiceMock = {
    sign: () => 'token',
    verify: () => ({ userId: 'user' }),
  };

  const mailerServiceMock = {
    sendVerificationEmail: async () => undefined,
    sendPasswordResetEmail: async () => undefined,
  };

  const imageModerationServiceMock = {
    assertImageIsSafe: async () => undefined,
  };

  const appleSignInServiceMock = {
    buildProfileFromAppPayload: async () => ({
      email: 'mock@example.com',
      name: 'Mock User',
      appleId: 'apple-id',
    }),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        AuthService,
        { provide: 'FIREBASE_APP', useValue: firebaseAppMock },
        { provide: JwtService, useValue: jwtServiceMock },
        { provide: MailerService, useValue: mailerServiceMock },
        { provide: ImageModerationService, useValue: imageModerationServiceMock },
        { provide: AppleSignInService, useValue: appleSignInServiceMock },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
