import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class SignupResponseDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({
    example: 'Verifizierungsmail gesendet. Bitte E-Mail innerhalb von 15 Minuten bestaetigen.',
  })
  message: string;
}

export class TokenPairDto {
  @ApiProperty({
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  accessToken: string;

  @ApiProperty({ example: '7c2f4a9a-9dcb-4a60-8bd2-2cb4bfa2c1ae' })
  refreshToken: string;
}

export class LoginResponseDto extends TokenPairDto {
  @ApiProperty({ example: 3 })
  loginStreak: number;

  @ApiProperty({ example: 7 })
  longestLoginStreak: number;
}

export class VerifyEmailResponseDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({ example: 'Email erfolgreich verifiziert' })
  message: string;

  @ApiPropertyOptional({ example: 'INVALID_TOKEN' })
  error?: string;

  @ApiPropertyOptional({ example: 'u9V8kB2m1' })
  userId?: string;

  @ApiPropertyOptional({ example: 'max@example.com' })
  email?: string;

  @ApiPropertyOptional({ example: 'Max Mustermann' })
  name?: string;
}

export class ProfileUpdateResponseDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({ example: 'Profil aktualisiert' })
  message: string;

  @ApiPropertyOptional({
    type: 'object',
    additionalProperties: true,
    example: { name: 'NeuerName', aboutMe: 'Kurztext' },
  })
  updates?: Record<string, unknown>;
}

export class ProfileAboutResponseDto {
  @ApiProperty({ example: 'Max Mustermann' })
  name: string;

  @ApiProperty({ example: 'Kurze Beschreibung zu mir' })
  aboutMe: string;
}

export class StreakResponseDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({ example: 4 })
  loginStreak: number;

  @ApiProperty({ example: 12 })
  longestLoginStreak: number;

  @ApiProperty({ example: '2026-04-18', nullable: true })
  lastLoginDate: string | null;
}

export class LessonPerformanceResponseDto {
  @ApiProperty({
    description: 'Matrix aus [lessonId, percentage] Eintraegen',
    type: 'array',
    items: {
      type: 'array',
      minItems: 2,
      maxItems: 2,
      items: { type: 'number' },
    },
    example: [
      [1, 100],
      [2, 75],
    ],
  })
  lessonPerformanceMatrix: number[][];
}

export class TestPerformanceResponseDto {
  @ApiProperty({
    description: 'Matrix aus [testId, percentage] Eintraegen',
    type: 'array',
    items: {
      type: 'array',
      minItems: 2,
      maxItems: 2,
      items: { type: 'number' },
    },
    example: [
      [1, 90],
      [2, 60],
    ],
  })
  testPerformanceMatrix: number[][];
}

export class DictionaryResponseDto {
  @ApiProperty({ type: [String], example: ['Hallo', 'Danke'] })
  dictionaryEntries: string[];
}

export class FavoriteGesturesResponseDto {
  @ApiProperty({ type: [String], example: ['A', 'B', 'C'] })
  favoriteGestures: string[];
}

export class BadgesResponseDto {
  @ApiProperty({
    description: 'Badges Matrix: [badgeId, status(0|1), unlockedAt]',
    type: 'array',
    items: {
      type: 'array',
      items: {
        oneOf: [{ type: 'number' }, { type: 'string', nullable: true }],
      },
    },
    example: [
      [1, 1, '2024-05-12T08:30:00.000Z'],
      [2, 0, null],
    ],
  })
  badges: Array<[number, number, string | null]>;
}

export class AvatarResponseDto {
  @ApiProperty({ example: 'https://storage.googleapis.com/...', nullable: true })
  avatarUrl: string | null;

  @ApiProperty({ example: 'image/png', nullable: true })
  avatarMimeType: string | null;

  @ApiProperty({ example: '2026-04-18T08:30:00.000Z', nullable: true })
  avatarUpdatedAt: string | null;

  @ApiPropertyOptional({ example: 1713429123000 })
  expiresAt?: number;
}

export class AvatarUploadResponseDto {
  @ApiProperty({ example: 'avatars/u9V8kB2m1/abc123.png' })
  avatarPath: string;

  @ApiProperty({ example: 'image/png' })
  avatarMimeType: string;
}

export class SuccessResponseDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiPropertyOptional({ example: 'OK' })
  message?: string;
}

export class FriendRequestDto {
  @ApiProperty({ example: 'req_123' })
  id: string;

  @ApiProperty({ example: 'u9V8kB2m1' })
  fromUserId: string;

  @ApiPropertyOptional({ example: 'Max' })
  username?: string | null;

  @ApiPropertyOptional({ example: 'https://storage.googleapis.com/...', nullable: true })
  avatarUrl?: string | null;

  @ApiProperty({ example: 4 })
  loginStreak: number;

  @ApiPropertyOptional({ example: '2026-04-18T08:30:00.000Z', nullable: true })
  createdAt?: unknown;
}

export class FriendRequestsResponseDto {
  @ApiProperty({ type: [FriendRequestDto] })
  requests: FriendRequestDto[];
}

export class FriendSummaryDto {
  @ApiProperty({ example: 'u9V8kB2m1' })
  userId: string;

  @ApiPropertyOptional({ example: 'Max' })
  username?: string | null;

  @ApiPropertyOptional({ example: 'https://storage.googleapis.com/...', nullable: true })
  avatarUrl?: string | null;

  @ApiProperty({ example: 4 })
  loginStreak: number;
}

export class FriendListResponseDto {
  @ApiProperty({ type: [FriendSummaryDto] })
  friends: FriendSummaryDto[];
}

export class SendFriendRequestResponseDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({ example: false })
  autoAccepted: boolean;

  @ApiPropertyOptional({ example: 'req_123' })
  requestId?: string;

  @ApiProperty({ example: 'Freundschaftsanfrage gesendet' })
  message: string;
}

export class RespondFriendRequestResponseDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({ example: true })
  accepted: boolean;

  @ApiProperty({ example: 'Freundschaftsanfrage akzeptiert' })
  message: string;
}
