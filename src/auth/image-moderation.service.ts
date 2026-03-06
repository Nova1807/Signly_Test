import {
  BadRequestException,
  Inject,
  Injectable,
  Logger,
  Optional,
} from '@nestjs/common';
import { GoogleAuth } from 'google-auth-library';

export type SafeSearchLikelihood =
  | 'UNKNOWN'
  | 'VERY_UNLIKELY'
  | 'UNLIKELY'
  | 'POSSIBLE'
  | 'LIKELY'
  | 'VERY_LIKELY';

export type SafeSearchCategory =
  | 'adult'
  | 'spoof'
  | 'medical'
  | 'violence'
  | 'racy';

interface SafeSearchAnnotation {
  adult?: SafeSearchLikelihood | null;
  spoof?: SafeSearchLikelihood | null;
  medical?: SafeSearchLikelihood | null;
  violence?: SafeSearchLikelihood | null;
  racy?: SafeSearchLikelihood | null;
}

interface VisionAnnotateResponse {
  responses?: Array<{
    safeSearchAnnotation?: SafeSearchAnnotation;
    error?: {
      message?: string;
      code?: number;
      status?: string;
    };
  }>;
}

export interface ImageModerationOptions {
  enabled?: boolean;
  defaultThreshold?: ThresholdInput;
  thresholds?: Partial<Record<SafeSearchCategory, ThresholdInput>>;
}

export const IMAGE_MODERATION_OPTIONS = 'IMAGE_MODERATION_OPTIONS';

type ThresholdInput =
  | number
  | SafeSearchLikelihood
  | 'OFF'
  | 'DISABLED'
  | 'IGNORE';

const SAFE_SEARCH_LIKELIHOODS: SafeSearchLikelihood[] = [
  'UNKNOWN',
  'VERY_UNLIKELY',
  'UNLIKELY',
  'POSSIBLE',
  'LIKELY',
  'VERY_LIKELY',
];

const SAFE_SEARCH_CATEGORIES: SafeSearchCategory[] = [
  'adult',
  'violence',
  'racy',
  'medical',
  'spoof',
];

@Injectable()
export class ImageModerationService {
  private readonly logger = new Logger(ImageModerationService.name);
  private readonly auth = new GoogleAuth({
    scopes: ['https://www.googleapis.com/auth/cloud-vision'],
  });
  private readonly enabled: boolean;
  private readonly thresholds: Record<SafeSearchCategory, number>;
  private clientPromise: Promise<any> | null = null;

  constructor(
    @Optional()
    @Inject(IMAGE_MODERATION_OPTIONS)
    options?: ImageModerationOptions,
  ) {
    this.enabled = options?.enabled ?? true;
    this.thresholds = this.buildThresholds(options);
  }

  async assertImageIsSafe(buffer: Buffer): Promise<void> {
    if (!this.enabled) {
      return;
    }

    if (!buffer || buffer.length === 0) {
      throw new BadRequestException('Ungültige Bilddaten');
    }

    const annotation = await this.requestSafeSearch(buffer);
    const violations = this.collectViolations(annotation);

    if (violations.length === 0) {
      return;
    }

    const readableViolations = violations
      .map(
        ({ category, likelihood }) =>
          `${this.describeCategory(category)} (${likelihood})`,
      )
      .join(', ');

    this.logger.warn(
      `safe-search rejected image due to: ${readableViolations}`,
    );

    throw new BadRequestException(
      `Das hochgeladene Bild verstößt gegen unsere Inhaltsrichtlinien (${readableViolations}).`,
    );
  }

  private async requestSafeSearch(buffer: Buffer): Promise<SafeSearchAnnotation> {
    try {
      const client = await this.getClient();
      const response = await client.request({
        url: 'https://vision.googleapis.com/v1/images:annotate',
        method: 'POST',
        data: {
          requests: [
            {
              image: { content: buffer.toString('base64') },
              features: [{ type: 'SAFE_SEARCH_DETECTION' }],
            },
          ],
        },
      });

      const data = response.data as VisionAnnotateResponse | undefined;
      const result = data?.responses?.[0];

      if (result?.error) {
        throw new Error(
          result.error.message ||
            `Vision API error (${result.error.status || result.error.code})`,
        );
      }

      if (!result?.safeSearchAnnotation) {
        throw new Error('SafeSearch annotation missing in response');
      }

      return result.safeSearchAnnotation;
    } catch (err: any) {
      this.logger.error(
        `safe-search request failed: ${err?.message || err}`,
        err?.stack,
      );
      throw new BadRequestException(
        'Das Bild konnte nicht überprüft werden. Bitte versuche es später erneut.',
      );
    }
  }

  private async getClient(): Promise<any> {
    if (!this.clientPromise) {
      this.clientPromise = this.auth.getClient();
    }
    return this.clientPromise;
  }

  private collectViolations(annotation: SafeSearchAnnotation) {
    return SAFE_SEARCH_CATEGORIES.filter((category) => {
      const threshold = this.thresholds[category];
      if (!Number.isFinite(threshold)) {
        return false;
      }

      const likelihood = this.parseLikelihood(annotation[category]);
      return likelihood >= threshold;
    }).map((category) => ({
      category,
      likelihood:
        annotation[category] ??
        SAFE_SEARCH_LIKELIHOODS[0],
    }));
  }

  private buildThresholds(
    options?: ImageModerationOptions,
  ): Record<SafeSearchCategory, number> {
    const defaultThreshold = this.normalizeThreshold(
      options?.defaultThreshold,
    ) ?? 4;
    const overrides = options?.thresholds ?? {};
    const entries = SAFE_SEARCH_CATEGORIES.map((category) => {
      const threshold = this.normalizeThreshold(overrides[category]) ?? defaultThreshold;
      return [category, threshold] as const;
    });

    return Object.fromEntries(entries) as Record<SafeSearchCategory, number>;
  }

  private normalizeThreshold(value?: ThresholdInput): number | undefined {
    if (value == null) {
      return undefined;
    }

    if (typeof value === 'number') {
      if (value === Number.POSITIVE_INFINITY) {
        return value;
      }
      if (value >= 0 && value <= 5) {
        return value;
      }
      return undefined;
    }

    const normalized = value.trim().toUpperCase();

    if (['IGNORE', 'SKIP', 'OFF', 'DISABLED'].includes(normalized)) {
      return Number.POSITIVE_INFINITY;
    }

    if (/^[0-5]$/.test(normalized)) {
      return Number.parseInt(normalized, 10);
    }

    const idx = SAFE_SEARCH_LIKELIHOODS.indexOf(
      normalized as SafeSearchLikelihood,
    );
    return idx >= 0 ? idx : undefined;
  }

  private parseLikelihood(input?: SafeSearchLikelihood | null): number {
    const idx = SAFE_SEARCH_LIKELIHOODS.indexOf(
      (input || 'UNKNOWN') as SafeSearchLikelihood,
    );
    return idx >= 0 ? idx : 0;
  }

  private describeCategory(category: SafeSearchCategory) {
    switch (category) {
      case 'adult':
        return 'explizite Inhalte';
      case 'racy':
        return 'sexuell anzügliche Inhalte';
      case 'violence':
        return 'Gewaltdarstellungen';
      case 'medical':
        return 'medizinische oder verletzende Inhalte';
      case 'spoof':
        return 'manipulierte Inhalte';
      default:
        return category;
    }
  }
}
