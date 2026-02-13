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
import { GlbService } from './glb.service';
import { MailerService } from './mailer.service';
import { AppleSignInService } from './apple/apple-signin.service';

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
    GlbService,
    MailerService,
  ],
})
export class AuthModule {}
