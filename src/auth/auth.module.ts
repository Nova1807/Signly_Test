import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { FirebaseModule } from '../firebase/firebase.module';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    FirebaseModule,
    // Falls noch nicht vorhanden: JWT-Konfiguration (SECRET via ENV setzen!)
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'dev-secret', // in Prod ENV benutzen
      signOptions: { expiresIn: '1h' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
