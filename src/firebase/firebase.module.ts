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

          // Falls du sicherstellen willst, dass die Standard-DB verwendet wird:
          admin.firestore().settings({
            databaseId: '(default)',
          });

          console.log('FIREBASE INIT', { projectId });
        }

        return admin.app();
      },
      inject: [ConfigService],
    },
  ],
  exports: ['FIREBASE_APP'],
})
export class FirebaseModule {}
