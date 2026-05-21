import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import { SIGN_CATALOG, type SignCatalogEntry } from './signs.catalog';
import { SignResponseDto } from './dto/sign-response.dto';
import { SignUpdateCheckDto } from './dto/sign-update-check.dto';
import { CheckUserSignsDto, UserSignCheckDto } from './dto/check-user-signs.dto';

@Injectable()
export class SignsService {
  private readonly logger = new Logger(SignsService.name);

  private readonly signs = SIGN_CATALOG;

  /**
   * Alle Gebärden abrufen
   */
  async getAllSigns(): Promise<SignResponseDto[]> {
    return this.signs.map((sign) => this.toResponseDto(sign));
  }

  /**
   * Gebärden abrufen, die ein Update benötigen
   */
  async getSignsNeedingUpdate(): Promise<SignResponseDto[]> {
    return [];
  }

  /**
   * Bestimmte Gebärden abrufen (optional nach Kategorie filtern)
   */
  async getSigns(category?: string): Promise<SignResponseDto[]> {
    const filteredSigns = category
      ? this.signs.filter((sign) => sign.category === category)
      : this.signs;

    return filteredSigns.map((sign) => this.toResponseDto(sign));
  }

  /**
   * Gebärden nach ID abrufen
   */
  async getSignById(id: string): Promise<SignResponseDto | null> {
    const sign = this.signs.find((entry) => entry.id === id);
    return sign ? this.toResponseDto(sign) : null;
  }

  /**
   * Gebärde löschen
   */
  async deleteSign(id: string): Promise<SignResponseDto | null> {
    return this.getSignById(id);
  }

  /**
   * Alle Gebärden auf Updates prüfen
   */
  async checkAllSignsForUpdates(): Promise<SignResponseDto[]> {
    const updatedSigns: SignResponseDto[] = [];

    for (const sign of this.signs) {
      try {
        const response = await axios.head(sign.glbUrl, { timeout: 10000 });
        const eTag = response.headers['etag'];
        const lastModified = response.headers['last-modified'];
        if (eTag || lastModified) {
          updatedSigns.push(this.toResponseDto(sign));
        }
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        this.logger.warn(`Update-Check fehlgeschlagen für ${sign.name}: ${err.message}`);
      }
    }

    return updatedSigns;
  }

  /**
   * Prüfe ob die User-seitigen Gebärden Updates brauchen
   * Der User schickt seine lokalen Gebärden-IDs und deren ETags/LastModified.
   * Der Server prüft diese gegen die aktuellen Header der GCS-Dateien.
   */
  async checkUserSigns(
    userSigns: UserSignCheckDto[],
  ): Promise<SignUpdateCheckDto[]> {
    const results: SignUpdateCheckDto[] = [];

    for (const userSign of userSigns) {
      const sign = this.signs.find((entry) => entry.id === userSign.signId);
      if (!sign) {
        results.push({
          signId: userSign.signId,
          name: 'UNBEKANNT',
          hasUpdate: false,
          reason: 'Gebärde nicht in der Liste gefunden',
        });
        continue;
      }

      try {
        const response = await axios.head(sign.glbUrl, { timeout: 10000 });
        const serverETag = response.headers['etag'];
        const serverLastModifiedHeader = response.headers['last-modified'];
        const serverLastModified = serverLastModifiedHeader
          ? new Date(serverLastModifiedHeader)
          : undefined;

        let hasUpdate = false;
        let reason = 'Keine Updates vorhanden';

        if (serverETag && userSign.localETag && serverETag !== userSign.localETag) {
          hasUpdate = true;
          reason = 'ETag geändert';
        } else if (
          serverLastModified &&
          userSign.localLastModified &&
          serverLastModified > new Date(userSign.localLastModified)
        ) {
          hasUpdate = true;
          reason = 'Last-Modified geändert';
        }

        results.push({
          signId: sign.id,
          name: sign.name,
          hasUpdate,
          serverETag,
          serverLastModified,
          reason,
        });
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        results.push({
          signId: sign.id,
          name: sign.name,
          hasUpdate: false,
          reason: `Konnte Cloud-Version nicht prüfen: ${err.message}`,
        });
      }
    }

    return results;
  }

  private toResponseDto(sign: SignCatalogEntry): SignResponseDto {
    return {
      id: sign.id,
      name: sign.name,
      glbUrl: sign.glbUrl,
      category: sign.category,
      needsUpdate: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }
}
