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
            'signly-be33f'; // Projekt-ID aus der URL

          const databaseId =
            configService.get<string>('FIRESTORE_DATABASE_ID') ||
            'signlydb'; // HIER deine DB-ID aus der UI

          admin.initializeApp({
            credential: admin.credential.applicationDefault(),
            projectId,
          });

          const fs = admin.firestore();

          // WICHTIG: explizit deine Enterprise-DB setzen
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
