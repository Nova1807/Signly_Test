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
            configService.get<string>('FIREBASE_PROJECT_ID') ||
            configService.get<string>('PROJECT_ID') ||
            'signly-be33f'; // hier dein GCP/Firebase-Projekt eintragen

          admin.initializeApp({
            credential: admin.credential.applicationDefault(),
            projectId,
          });

          const fs = admin.firestore();
          console.log('FIREBASE INIT', {
            projectId: admin.app().options.projectId,
            // interne Info, um zu sehen welche DB genutzt wird
            databaseId: (fs as any)._databaseId,
          });

          // Falls du ausdrücklich die Default-DB erzwingen willst:
          fs.settings({
            databaseId: '(default)',
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
