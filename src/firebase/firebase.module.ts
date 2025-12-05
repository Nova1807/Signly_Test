import { Module } from '@nestjs/common';
import * as admin from 'firebase-admin';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [ConfigModule],
  providers: [
    {
      provide: 'FIREBASE_APP',
      useFactory: (configService: ConfigService) => {
        if (!admin.apps.length) {
          const projectId =
            configService.get<string>('FIREBASE_PROJECT_ID') || 'signly-be33f';

          const databaseId =
            configService.get<string>('FIRESTORE_DATABASE_ID') || 'signlydb';

          admin.initializeApp({
            credential: admin.credential.applicationDefault(),
            projectId,
          });

          const fs = admin.firestore();

          fs.settings({
            databaseId,
          });

          console.log('FIREBASE INIT', {
            projectId: admin.app().options.projectId,
            databaseId: (fs as any)._databaseId,
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
