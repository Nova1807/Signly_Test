import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { MailerService } from './mailer.service';
import { ImageModerationService } from './image-moderation.service';

describe('AuthService', () => {
  let service: AuthService;

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

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: 'FIREBASE_APP', useValue: firebaseAppMock },
        { provide: JwtService, useValue: jwtServiceMock },
        { provide: MailerService, useValue: mailerServiceMock },
        { provide: ImageModerationService, useValue: imageModerationServiceMock },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
