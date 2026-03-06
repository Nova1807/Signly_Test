// src/auth/auth.module.ts

import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { FirebaseModule } from '../firebase/firebase.module';
import { EmailAssetsController } from './email-assets.controller';
import { GoogleStrategy } from './strategies/google.strategy';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { MailerService } from './mailer.service';
import { AppleSignInService } from './apple/apple-signin.service';
import {
  ImageModerationService,
  IMAGE_MODERATION_OPTIONS,
  ImageModerationOptions,
} from './image-moderation.service';

const imageModerationDefaults: ImageModerationOptions = {
  enabled: true,
  defaultThreshold: 'LIKELY',
};

@Module({
  imports: [
    FirebaseModule,
    PassportModule.register({ defaultStrategy: 'google' }),
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'dev-secret',
      signOptions: { expiresIn: '1h' },
    }),
  ],
  controllers: [AuthController, EmailAssetsController],
  providers: [
    AuthService,
    GoogleStrategy,
    GoogleAuthGuard,
    AppleSignInService,
    MailerService,
    ImageModerationService,
    {
      provide: IMAGE_MODERATION_OPTIONS,
      useValue: imageModerationDefaults,
    },
  ],
})
export class AuthModule {}
