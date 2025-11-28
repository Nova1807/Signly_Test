import { Module } from '@nestjs/common';
import * as admin from 'firebase-admin';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [ConfigModule],
  providers: [
    {
      provide: 'FIREBASE_APP',
      useFactory: (configService: ConfigService) => {
        const serviceAccount = require(configService.get('firebase.serviceAccountPath') || './signly-be33f-firebase-adminsdk-fbsvc-cd21369526.json');
        return admin.initializeApp({
          credential: admin.credential.cert(serviceAccount),
          databaseURL: configService.get('firebase.databaseURL'),
        });
      },
      inject: [ConfigService],
    },
  ],
  exports: ['FIREBASE_APP'],
})
export class FirebaseModule {}
