import { Injectable, Logger, UnauthorizedException, ForbiddenException, Inject } from '@nestjs/common';
import * as admin from 'firebase-admin';

@Injectable()
export class GlbService {
  private readonly logger = new Logger(GlbService.name);

  constructor(@Inject('FIREBASE_APP') private readonly firebaseApp: admin.app.App) {}

  async validateGlbToken(accessToken: string, requestedFile?: string) {
    const firestore = this.firebaseApp.firestore();
    const tokenDocRef = firestore.collection('glbAccessTokens').doc(accessToken);
    const tokenDoc = await tokenDocRef.get();

    if (!tokenDoc.exists) {
      this.logger.warn('validateGlbToken: access token not found');
      throw new UnauthorizedException('Invalid access token');
    }

    const tokenData = tokenDoc.data() as any;
    if (!tokenData) {
      this.logger.warn('validateGlbToken: token doc empty');
      throw new UnauthorizedException('Invalid access token');
    }

    if (tokenData.expiresAt) {
      const expiresAt: Date =
        typeof tokenData.expiresAt.toDate === 'function'
          ? tokenData.expiresAt.toDate()
          : new Date(tokenData.expiresAt);

      if (expiresAt.getTime() < Date.now()) {
        this.logger.log('validateGlbToken: token expired');
        throw new UnauthorizedException('Access token expired');
      }
    }

    if (
      tokenData.allowedFiles &&
      Array.isArray(tokenData.allowedFiles) &&
      requestedFile
    ) {
      if (!tokenData.allowedFiles.includes(requestedFile)) {
        this.logger.warn('validateGlbToken: token not allowed for requested file');
        throw new ForbiddenException('Token not allowed for this file');
      }
    }

    return tokenData;
  }

  sanitizeFilePath(file: string) {
    return file.replace(/^\/+/, '').replace(/\.\./g, '');
  }

  async streamGlbFromStorage(safeFile: string, res: any) {
    const bucket = this.firebaseApp.storage().bucket();
    const remoteFile = bucket.file(safeFile);

    const [exists] = await remoteFile.exists();
    if (!exists) {
      this.logger.warn(`streamGlbFromStorage: file not found ${safeFile}`);
      res.status(404).json({ error: 'File not found' });
      return;
    }

    res.setHeader('Content-Type', 'model/gltf-binary');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${safeFile.split('/').pop()}"`,
    );

    const stream = remoteFile.createReadStream();
    stream.on('error', (err) => {
      this.logger.error(`streamGlbFromStorage stream error: ${err?.message}`, err?.stack);
      if (!res.headersSent) {
        res.status(500).json({ error: 'Error streaming file' });
      } else {
        try {
          res.end();
        } catch (_) {}
      }
    });

    stream.pipe(res);
  }
}
