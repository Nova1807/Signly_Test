import { BadRequestException, Logger } from '@nestjs/common';
import * as admin from 'firebase-admin';
import { v4 as uuidv4 } from 'uuid';
import sharp from 'sharp';
import { ImageModerationService } from '../image-moderation.service';
import {
  formatLogContext,
  maskId,
} from '../../common/logging/redaction';
import { UserCollectionsManager } from './user-collections.manager';

export type AvatarUploadFile = {
  buffer: Buffer;
  mimetype: string;
  size: number;
};

export interface AvatarManagerOptions {
  firebaseApp: admin.app.App;
  logger: Logger;
  avatarFolder: string;
  maxAvatarBytes: number;
  allowedAvatarMimeTypes: ReadonlySet<string>;
  avatarSignedUrlExpiresInMs: number;
  avatarJpegQuality: number;
  avatarWebpQuality: number;
  avatarPngCompressionLevel: number;
  imageModerationService: ImageModerationService;
  userCollectionsManager: UserCollectionsManager;
}

export class AvatarManager {
  constructor(private readonly options: AvatarManagerOptions) {}

  private get storageBucket() {
    return this.options.firebaseApp.storage().bucket();
  }

  private get firestore() {
    return this.options.firebaseApp.firestore();
  }

  private detectAvatarExtension(mimeType: string) {
    if (mimeType === 'image/png') return 'png';
    if (mimeType === 'image/webp') return 'webp';
    return 'jpg';
  }

  private validateAvatarMagicBytes(buffer: Buffer, mimeType: string) {
    if (mimeType === 'image/png') {
      return buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47;
    }

    if (mimeType === 'image/jpeg') {
      return (
        buffer[0] === 0xff &&
        buffer[1] === 0xd8 &&
        buffer[buffer.length - 2] === 0xff &&
        buffer[buffer.length - 1] === 0xd9
      );
    }

    if (mimeType === 'image/webp') {
      return (
        buffer[0] === 0x52 &&
        buffer[1] === 0x49 &&
        buffer[2] === 0x46 &&
        buffer[3] === 0x46 &&
        buffer[8] === 0x57 &&
        buffer[9] === 0x45 &&
        buffer[10] === 0x42 &&
        buffer[11] === 0x50
      );
    }

    return false;
  }

  private normalizeAvatarMimeType(mimeType: string) {
    if (mimeType === 'image/jpg') return 'image/jpeg';
    if (mimeType === 'image/x-png') return 'image/png';
    return mimeType;
  }

  private sanitizeAvatarFile(file?: AvatarUploadFile) {
    if (!file) {
      throw new BadRequestException('avatar-Datei fehlt');
    }

    if (!file.buffer || !file.buffer.length) {
      throw new BadRequestException('avatar-Datei konnte nicht gelesen werden');
    }

    if (file.buffer.length > this.options.maxAvatarBytes) {
      throw new BadRequestException(
        `Avatar ist zu groß (max ${(this.options.maxAvatarBytes / (1024 * 1024)).toFixed(1)}MB)`,
      );
    }

    const mimeType = this.normalizeAvatarMimeType((file.mimetype || '').toLowerCase());
    if (!this.options.allowedAvatarMimeTypes.has(mimeType)) {
      throw new BadRequestException('Unterstützte Avatar-Typen: PNG, JPEG, WEBP');
    }

    if (file.buffer.length < 4) {
      throw new BadRequestException('Ungültiges Bildformat');
    }

    if (!this.validateAvatarMagicBytes(file.buffer, mimeType)) {
      throw new BadRequestException('Ungültiges Bildformat');
    }

    return { buffer: file.buffer, mimeType };
  }

  private async prepareAvatarFile(file?: AvatarUploadFile) {
    const sanitized = this.sanitizeAvatarFile(file);
    return this.optimizeAvatarBuffer(sanitized.buffer, sanitized.mimeType);
  }

  private async optimizeAvatarBuffer(buffer: Buffer, mimeType: string) {
    try {
      let optimized: Buffer;

      if (mimeType === 'image/png') {
        optimized = await sharp(buffer, { failOnError: true })
          .rotate()
          .png({
            compressionLevel: this.options.avatarPngCompressionLevel,
            adaptiveFiltering: true,
          })
          .toBuffer();
      } else if (mimeType === 'image/webp') {
        optimized = await sharp(buffer, { failOnError: true })
          .rotate()
          .webp({
            quality: this.options.avatarWebpQuality,
            effort: 4,
          })
          .toBuffer();
      } else {
        optimized = await sharp(buffer, { failOnError: true })
          .rotate()
          .jpeg({
            quality: this.options.avatarJpegQuality,
            mozjpeg: true,
          })
          .toBuffer();
      }

      return { buffer: optimized, mimeType };
    } catch (err: any) {
      this.options.logger.warn(
        `optimizeAvatarBuffer: returning original buffer due to error: ${err?.message}`,
      );
      return { buffer, mimeType };
    }
  }

  async getAvatar(userId: string) {
    const { userDoc } = await this.options.userCollectionsManager.getUserDocument(userId);
    const data = userDoc.data() as any;
    const avatarPath = data?.avatarPath;
    if (!avatarPath) {
      return {
        avatarUrl: null,
        avatarMimeType: null,
        avatarUpdatedAt: data?.avatarUpdatedAt ?? null,
      };
    }

    const fileRef = this.storageBucket.file(avatarPath);
    const expiresAt = Date.now() + this.options.avatarSignedUrlExpiresInMs;

    try {
      const [url] = await fileRef.getSignedUrl({
        action: 'read',
        expires: expiresAt,
      });

      return {
        avatarUrl: url,
        avatarMimeType: data?.avatarMimeType ?? null,
        avatarUpdatedAt: data?.avatarUpdatedAt ?? null,
        expiresAt,
      };
    } catch (err: any) {
      this.options.logger.warn(
        `getAvatar: failed to sign URL (${err?.message})` +
          formatLogContext({
            path: avatarPath,
            userId: maskId(userId),
          }),
      );
      return {
        avatarUrl: null,
        avatarMimeType: null,
        avatarUpdatedAt: data?.avatarUpdatedAt ?? null,
      };
    }
  }

  async downloadAvatar(userId: string) {
    const { userDoc } = await this.options.userCollectionsManager.getUserDocument(userId);
    const data = userDoc.data() as any;
    const avatarPath = data?.avatarPath;

    if (!avatarPath) {
      throw new BadRequestException('Kein Avatar vorhanden');
    }

    const fileRef = this.storageBucket.file(avatarPath);
    const [exists] = await fileRef.exists();
    if (!exists) {
      throw new BadRequestException('Avatar wurde nicht gefunden');
    }

    return {
      stream: fileRef.createReadStream(),
      mimeType: data?.avatarMimeType ?? 'application/octet-stream',
    };
  }

  async uploadAvatar(userId: string, file?: AvatarUploadFile) {
    const { buffer, mimeType } = await this.prepareAvatarFile(file);
    await this.options.imageModerationService.assertImageIsSafe(buffer);
    const { userDoc, userRef } = await this.options.userCollectionsManager.getUserDocument(userId);
    const previousPath = (userDoc.data() as any)?.avatarPath;
    const extension = this.detectAvatarExtension(mimeType);
    const newPath = `${this.options.avatarFolder}/${userId}/${uuidv4()}.${extension}`;
    const fileRef = this.storageBucket.file(newPath);

    await fileRef.save(buffer, {
      resumable: false,
      contentType: mimeType,
      metadata: { cacheControl: 'private, max-age=0' },
    });

    if (previousPath) {
      try {
        await this.storageBucket.file(previousPath).delete({ ignoreNotFound: true });
      } catch (err: any) {
        this.options.logger.warn(
          `uploadAvatar: failed to delete old avatar (${err?.message})` +
            formatLogContext({
              previousPath,
              userId: maskId(userId),
            }),
        );
      }
    }

    await userRef.update({
      avatarPath: newPath,
      avatarMimeType: mimeType,
      avatarUpdatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    this.options.logger.log(
      'uploadAvatar: stored avatar' +
        formatLogContext({
          userId: maskId(userId),
          path: newPath,
          bytes: buffer.length,
        }),
    );

    return {
      avatarPath: newPath,
      avatarMimeType: mimeType,
    };
  }

  async deleteAvatar(userId: string) {
    const { userDoc, userRef } = await this.options.userCollectionsManager.getUserDocument(userId);
    const data = userDoc.data() as any;
    const avatarPath = data?.avatarPath;

    if (avatarPath) {
      try {
        await this.storageBucket.file(avatarPath).delete({ ignoreNotFound: true });
      } catch (err: any) {
        this.options.logger.warn(
          `deleteAvatar: failed to delete avatar (${err?.message})` +
            formatLogContext({
              path: avatarPath,
              userId: maskId(userId),
            }),
        );
      }
    }

    await userRef.update({
      avatarPath: admin.firestore.FieldValue.delete(),
      avatarMimeType: admin.firestore.FieldValue.delete(),
      avatarUpdatedAt: admin.firestore.FieldValue.delete(),
    });

    this.options.logger.log(
      'deleteAvatar: removed avatar metadata' +
        formatLogContext({
          userId: maskId(userId),
        }),
    );
    return { success: true };
  }
}
