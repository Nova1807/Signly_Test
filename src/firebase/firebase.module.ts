import { Module } from '@nestjs/common';
import * as admin from 'firebase-admin';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [ConfigModule],
  providers: [
    {
      provide: 'FIREBASE_APP',
      useFactory: (configService: ConfigService) => {
        const serviceAccountPath =
          configService.get<string>('FIREBASE_SERVICE_ACCOUNT_KEY_PATH') ||
          process.env.FIREBASE_SERVICE_ACCOUNT_KEY_PATH ||
          './signly-be33f-firebase-adminsdk-fbsvc-cd21369526.json';

        // @ts-ignore
        const serviceAccount = require(serviceAccountPath);

        if (!admin.apps.length) {
          admin.initializeApp({
            credential: admin.credential.cert(serviceAccount),
          });
        }

        return admin.app();
      },
      inject: [ConfigService],
    },
  ],
  exports: ['FIREBASE_APP'],
})
export class FirebaseModule {}
