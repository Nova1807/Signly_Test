import { BadRequestException, Logger } from '@nestjs/common';
import * as admin from 'firebase-admin';
import {
  formatLogContext,
  maskId,
} from '../../common/logging/redaction';

export type PerformanceKind = 'lesson' | 'test';
export type PerformanceMatrixKey = 'lessonPerformanceMatrix' | 'testPerformanceMatrix';

export interface UserDocumentResult {
  userDoc: admin.firestore.DocumentSnapshot;
  userRef: admin.firestore.DocumentReference;
}

export interface UserCollectionsManagerOptions {
  firebaseApp: admin.app.App;
  logger: Logger;
  lessonIdSet: Set<number>;
  testIdSet: Set<number>;
}

export class UserCollectionsManager {
  constructor(private readonly options: UserCollectionsManagerOptions) {}

  private get firestore() {
    return this.options.firebaseApp.firestore();
  }

  private clampPercentage(value: number): number {
    if (!Number.isFinite(value)) {
      return 0;
    }
    return Math.max(0, Math.min(100, value));
  }

  private arraysEqual(a: any, b: any): boolean {
    return JSON.stringify(a ?? []) === JSON.stringify(b ?? []);
  }

  private normalizeStringArray(value: any): string[] {
    if (!Array.isArray(value)) {
      return [];
    }
    const seen = new Set<string>();
    const normalized: string[] = [];
    for (const entry of value) {
      if (typeof entry !== 'string') {
        continue;
      }
      const trimmed = entry.trim();
      if (!trimmed || seen.has(trimmed)) {
        continue;
      }
      normalized.push(trimmed);
      seen.add(trimmed);
    }
    return normalized;
  }

  private sanitizeStringArrayInput(value: any, fieldName: string): string[] {
    if (!Array.isArray(value)) {
      throw new BadRequestException(`${fieldName} muss ein Array aus Strings sein`);
    }
    const invalid = value.some((entry) => typeof entry !== 'string');
    if (invalid) {
      throw new BadRequestException(`${fieldName} darf nur Strings enthalten`);
    }
    return this.normalizeStringArray(value);
  }

  private getMatrixKey(kind: PerformanceKind): PerformanceMatrixKey {
    return kind === 'lesson' ? 'lessonPerformanceMatrix' : 'testPerformanceMatrix';
  }

  private getAllowedIdSet(kind: PerformanceKind): Set<number> | undefined {
    const source = kind === 'lesson' ? this.options.lessonIdSet : this.options.testIdSet;
    return source.size > 0 ? source : undefined;
  }

  private normalizePerformanceMatrixInput(value: any, kind: PerformanceKind, strict = false) {
    const allowedSet = this.getAllowedIdSet(kind);

    if (!Array.isArray(value)) {
      if (strict && value !== undefined) {
        throw new BadRequestException(
          kind === 'lesson'
            ? 'lessonPerformanceMatrix muss ein Array sein'
            : 'testPerformanceMatrix muss ein Array sein',
        );
      }
      return [] as number[][];
    }

    const sanitized = new Map<number, number>();

    for (const rawEntry of value) {
      if (rawEntry === undefined || rawEntry === null) {
        continue;
      }

      let idValue: any;
      let percentageValue: any;

      if (Array.isArray(rawEntry) && rawEntry.length >= 2) {
        [idValue, percentageValue] = rawEntry;
      } else if (typeof rawEntry === 'object') {
        idValue = (rawEntry as any).lessonId ?? (rawEntry as any).testId ?? (rawEntry as any).id;
        percentageValue = (rawEntry as any).percentage ?? (rawEntry as any).value;
      } else {
        if (strict) {
          throw new BadRequestException(
            kind === 'lesson'
              ? 'lessonPerformanceMatrix erwartet lessonId & percentage'
              : 'testPerformanceMatrix erwartet testId & percentage',
          );
        }
        continue;
      }

      const numericId = Number(idValue);
      const numericPercentage = Number(percentageValue);

      if (!Number.isFinite(numericId) || !Number.isFinite(numericPercentage)) {
        if (strict) {
          throw new BadRequestException(
            kind === 'lesson'
              ? 'lessonPerformanceMatrix benötigt numerische lessonId & percentage'
              : 'testPerformanceMatrix benötigt numerische testId & percentage',
          );
        }
        continue;
      }

      const normalizedId = Math.floor(numericId);
      if (allowedSet && !allowedSet.has(normalizedId)) {
        const message = kind === 'lesson' ? 'Unknown lessonId' : 'Unknown testId';
        if (strict) {
          throw new BadRequestException(message);
        }
        continue;
      }

      sanitized.set(normalizedId, this.clampPercentage(numericPercentage));
    }

    return Array.from(sanitized.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([id, percentage]) => [id, percentage]);
  }

  private normalizeBadgesMatrix(
    value: any,
    strict = false,
  ): Array<[number, number, string | null]> {
    if (!Array.isArray(value)) {
      if (strict && value !== undefined) {
        throw new BadRequestException('badges muss ein zweidimensionales Array sein');
      }
      return [];
    }

    const result = new Map<number, { state: number; unlockedAt: string | null }>();

    const normalizeUnlockedAt = (raw: any): string | null => {
      if (typeof raw !== 'string') {
        return null;
      }
      const trimmed = raw.trim();
      if (!trimmed) {
        return null;
      }
      const parsed = new Date(trimmed);
      if (Number.isNaN(parsed.getTime())) {
        return null;
      }
      return parsed.toISOString();
    };

    const allowLegacyMatrixFormat = !strict;
    const isLegacyMatrixFormat =
      allowLegacyMatrixFormat &&
      (value.length === 2 || value.length === 3) &&
      Array.isArray(value[0]) &&
      Array.isArray(value[1]) &&
      value[0].length === value[1].length &&
      value[0].every((entry: any) => Number.isFinite(Number(entry))) &&
      value[1].every((entry: any) => {
        const numeric = Number(entry);
        return Number.isFinite(numeric) && (numeric === 0 || numeric === 1);
      });

    const pushEntry = (idValue: any, stateValue: any, unlockedValue: any, allowUnlockedInput: boolean) => {
      const numericId = Number(idValue);
      const numericState = Number(stateValue);

      if (!Number.isFinite(numericId) || !Number.isFinite(numericState)) {
        if (strict) {
          throw new BadRequestException('badges benötigt numerische badgeId und wert');
        }
        return;
      }

      const normalizedId = Math.floor(numericId);
      if (normalizedId < 0) {
        if (strict) {
          throw new BadRequestException('badgeId darf nicht negativ sein');
        }
        return;
      }

      if (numericState !== 0 && numericState !== 1) {
        if (strict) {
          throw new BadRequestException('badge-wert darf nur 0 oder 1 sein');
        }
        return;
      }

      result.set(normalizedId, {
        state: numericState,
        unlockedAt: allowUnlockedInput ? normalizeUnlockedAt(unlockedValue) : null,
      });
    };

    if (isLegacyMatrixFormat) {
      const [ids, states, timestamps] = value as [any[], any[], any[]?];
      const unlockedList = Array.isArray(timestamps) ? timestamps : [];
      ids.forEach((idValue, index) => {
        pushEntry(idValue, states[index], unlockedList[index], true);
      });
    } else {
      for (const rawEntry of value) {
        if (rawEntry === undefined || rawEntry === null) {
          continue;
        }

        let idValue: any;
        let stateValue: any;
        let unlockedValue: any;

        if (Array.isArray(rawEntry) && rawEntry.length >= 2) {
          [idValue, stateValue, unlockedValue] = rawEntry;
        } else if (typeof rawEntry === 'object') {
          idValue = (rawEntry as any).badgeId ?? (rawEntry as any).id;
          stateValue = (rawEntry as any).value ?? (rawEntry as any).state;
          unlockedValue =
            (rawEntry as any).unlockedAt ??
            (rawEntry as any).unlockDate ??
            (rawEntry as any).timestamp;
        } else {
          if (strict) {
            throw new BadRequestException(
              'badges erwartet [badgeId, wert] oder entsprechende Objekte',
            );
          }
          continue;
        }

        pushEntry(idValue, stateValue, unlockedValue, !strict);
      }
    }

    const sorted = Array.from(result.entries()).sort((a, b) => a[0] - b[0]);
    return sorted.map(([id, payload]) => [id, payload.state, payload.unlockedAt ?? null]);
  }

  async ensureUserCollections(
    userDoc: admin.firestore.QueryDocumentSnapshot | admin.firestore.DocumentSnapshot,
  ): Promise<void> {
    const data = userDoc.data();
    if (!data) return;

    const updates: Record<string, any> = {};

    const normalizedLesson = this.normalizePerformanceMatrixInput(
      data.lessonPerformanceMatrix,
      'lesson',
    );
    if (!this.arraysEqual(data.lessonPerformanceMatrix, normalizedLesson)) {
      updates.lessonPerformanceMatrix = normalizedLesson;
    }

    const normalizedTest = this.normalizePerformanceMatrixInput(data.testPerformanceMatrix, 'test');
    if (!this.arraysEqual(data.testPerformanceMatrix, normalizedTest)) {
      updates.testPerformanceMatrix = normalizedTest;
    }

    const normalizedDictionary = this.normalizeStringArray(data.dictionaryEntries);
    if (!this.arraysEqual(data.dictionaryEntries, normalizedDictionary)) {
      updates.dictionaryEntries = normalizedDictionary;
    }

    const normalizedFavorites = this.normalizeStringArray(data.favoriteGestures);
    if (!this.arraysEqual(data.favoriteGestures, normalizedFavorites)) {
      updates.favoriteGestures = normalizedFavorites;
    }

    const normalizedBadges = this.normalizeBadgesMatrix((data as any).badges);
    if (!this.arraysEqual((data as any).badges, normalizedBadges)) {
      updates.badges = normalizedBadges;
    }

    if (Object.keys(updates).length > 0) {
      await userDoc.ref.update(updates);
      this.options.logger.log(
        'ensureUserCollections: normalized arrays' +
          formatLogContext({
            userId: maskId(userDoc.id),
            updatedFields: Object.keys(updates),
          }),
      );
    }
  }

  async getUserDocument(userId: string): Promise<UserDocumentResult> {
    const userRef = this.firestore.collection('users').doc(userId);
    const userDoc = await userRef.get();
    if (!userDoc.exists) {
      this.options.logger.warn(
        'getUserDocument: user not found' +
          formatLogContext({
            userId: maskId(userId),
          }),
      );
      throw new BadRequestException('User not found');
    }
    await this.ensureUserCollections(userDoc);
    return { userDoc, userRef };
  }

  private mergePerformanceEntry(matrix: number[][], entryId: number, percentage: number) {
    const next = matrix.map(([id, value]) => [id, value]);
    const existingIndex = next.findIndex(([id]) => id === entryId);

    if (existingIndex >= 0) {
      next[existingIndex][1] = percentage;
    } else {
      next.push([entryId, percentage]);
    }

    next.sort((a, b) => a[0] - b[0]);
    return next;
  }

  async updatePerformanceMatrix(
    userId: string,
    matrixKey: PerformanceMatrixKey,
    entryId: number,
    percentage: number,
  ): Promise<number[][]> {
    const kind: PerformanceKind = matrixKey === 'lessonPerformanceMatrix' ? 'lesson' : 'test';
    const allowedSet = this.getAllowedIdSet(kind);
    const normalizedEntryId = Math.floor(Number(entryId));

    if (!Number.isFinite(normalizedEntryId)) {
      this.options.logger.warn(
        'updatePerformanceMatrix: invalid entry id' +
          formatLogContext({
            kind,
            entryId,
            userId: maskId(userId),
          }),
      );
      throw new BadRequestException(
        kind === 'lesson' ? 'lessonId ist ungültig' : 'testId ist ungültig',
      );
    }

    if (allowedSet && !allowedSet.has(normalizedEntryId)) {
      this.options.logger.warn(
        `updatePerformanceMatrix: entryId ${normalizedEntryId} not allowed for ${matrixKey}`,
      );
      throw new BadRequestException(
        matrixKey === 'lessonPerformanceMatrix' ? 'Unknown lessonId' : 'Unknown testId',
      );
    }

    const clampedPercentage = this.clampPercentage(percentage);
    const userRef = this.firestore.collection('users').doc(userId);

    const updatedMatrix = await this.firestore.runTransaction(async (tx) => {
      const userSnap = await tx.get(userRef);
      if (!userSnap.exists) {
        this.options.logger.warn(
          'updatePerformanceMatrix: user not found' +
            formatLogContext({
              userId: maskId(userId),
            }),
        );
        throw new BadRequestException('User not found');
      }

      const data = userSnap.data() || {};
      const matrix = this.normalizePerformanceMatrixInput(data[matrixKey], kind);
      const next = this.mergePerformanceEntry(matrix, normalizedEntryId, clampedPercentage);

      tx.update(userRef, {
        [matrixKey]: next,
      });

      return next;
    });

    this.options.logger.log(
      'updatePerformanceMatrix: updated entry' +
        formatLogContext({
          matrixKey,
          userId: maskId(userId),
          entryId: normalizedEntryId,
          percentage: clampedPercentage,
        }),
    );

    return updatedMatrix;
  }

  async replacePerformanceMatrix(
    userId: string,
    kind: PerformanceKind,
    entries: { id: number; percentage: number }[],
  ): Promise<number[][]> {
    const matrixKey = this.getMatrixKey(kind);
    const payload = entries.map((entry) => [entry.id, entry.percentage]);
    const normalized = this.normalizePerformanceMatrixInput(payload, kind, true);
    const { userRef } = await this.getUserDocument(userId);

    await userRef.update({
      [matrixKey]: normalized,
    });

    this.options.logger.log(
      'replacePerformanceMatrix: replaced matrix' +
        formatLogContext({
          matrixKey,
          userId: maskId(userId),
          entries: normalized.length,
        }),
    );

    return normalized;
  }

  async getLessonPerformance(userId: string) {
    const { userDoc } = await this.getUserDocument(userId);
    const data = userDoc.data() as any;
    return {
      lessonPerformanceMatrix: this.normalizePerformanceMatrixInput(
        data?.lessonPerformanceMatrix,
        'lesson',
      ),
    };
  }

  async updateLessonPerformance(userId: string, lessonId: number, percentage: number) {
    const lessonPerformanceMatrix = await this.updatePerformanceMatrix(
      userId,
      'lessonPerformanceMatrix',
      lessonId,
      percentage,
    );
    return { lessonPerformanceMatrix };
  }

  async getTestPerformance(userId: string) {
    const { userDoc } = await this.getUserDocument(userId);
    const data = userDoc.data() as any;
    return {
      testPerformanceMatrix: this.normalizePerformanceMatrixInput(
        data?.testPerformanceMatrix,
        'test',
      ),
    };
  }

  async updateTestPerformance(userId: string, testId: number, percentage: number) {
    const testPerformanceMatrix = await this.updatePerformanceMatrix(
      userId,
      'testPerformanceMatrix',
      testId,
      percentage,
    );
    return { testPerformanceMatrix };
  }

  async setLessonPerformanceMatrix(
    userId: string,
    entries: { id: number; percentage: number }[],
  ) {
    const lessonPerformanceMatrix = await this.replacePerformanceMatrix(userId, 'lesson', entries);
    return { lessonPerformanceMatrix };
  }

  async setTestPerformanceMatrix(
    userId: string,
    entries: { id: number; percentage: number }[],
  ) {
    const testPerformanceMatrix = await this.replacePerformanceMatrix(userId, 'test', entries);
    return { testPerformanceMatrix };
  }

  async getDictionaryEntries(userId: string) {
    const { userDoc } = await this.getUserDocument(userId);
    const data = userDoc.data() as any;
    return {
      dictionaryEntries: this.normalizeStringArray(data?.dictionaryEntries),
    };
  }

  async updateDictionaryEntries(userId: string, entries: string[]) {
    const sanitized = this.sanitizeStringArrayInput(entries, 'dictionaryEntries');
    const { userRef } = await this.getUserDocument(userId);
    await userRef.update({ dictionaryEntries: sanitized });
    this.options.logger.log(
      `updateDictionaryEntries: stored ${sanitized.length} entries for ${userId}`,
    );
    return { dictionaryEntries: sanitized };
  }

  async getFavoriteGestures(userId: string) {
    const { userDoc } = await this.getUserDocument(userId);
    const data = userDoc.data() as any;
    return {
      favoriteGestures: this.normalizeStringArray(data?.favoriteGestures),
    };
  }

  async updateFavoriteGestures(userId: string, entries: string[]) {
    const sanitized = this.sanitizeStringArrayInput(entries, 'favoriteGestures');
    const { userRef } = await this.getUserDocument(userId);
    await userRef.update({ favoriteGestures: sanitized });
    this.options.logger.log(
      `updateFavoriteGestures: stored ${sanitized.length} favorite gestures for ${userId}`,
    );
    return { favoriteGestures: sanitized };
  }

  async getBadges(userId: string) {
    const { userDoc } = await this.getUserDocument(userId);
    const data = userDoc.data() as any;
    return {
      badges: this.normalizeBadgesMatrix(data?.badges),
    };
  }

  async updateBadges(userId: string, badges: number[][]) {
    const incoming = this.normalizeBadgesMatrix(badges, true);
    const { userDoc, userRef } = await this.getUserDocument(userId);
    const existing = this.normalizeBadgesMatrix((userDoc.data() as any)?.badges);

    const existingMap = new Map<number, { state: number; unlockedAt: string | null }>();
    existing.forEach(([id, state, unlockedAt]) => {
      existingMap.set(id, { state, unlockedAt: unlockedAt ?? null });
    });

    const updated = incoming.map(([id, state]) => {
      const previous = existingMap.get(id);
      let unlockedAt = previous?.unlockedAt ?? null;

      if (state === 1 && previous?.state !== 1) {
        unlockedAt = new Date().toISOString();
      }

      if (state === 0) {
        unlockedAt = null;
      }

      return [id, state, unlockedAt] as [number, number, string | null];
    });

    await userRef.update({ badges: updated });
    return { badges: updated };
  }

  async getProfileAbout(userId: string) {
    const { userDoc } = await this.getUserDocument(userId);
    const data = userDoc.data() as any;
    return {
      name: data?.name ?? '',
      aboutMe: data?.aboutMe ?? '',
    };
  }

  async getStreak(userId: string) {
    const { userDoc } = await this.getUserDocument(userId);
    const user = userDoc.data() as any;
    return {
      success: true,
      loginStreak: (user && (user.loginStreak as number)) || 0,
      longestLoginStreak: (user && (user.longestLoginStreak as number)) || 0,
      lastLoginDate: (user && user.lastLoginDate) || null,
    };
  }
}
