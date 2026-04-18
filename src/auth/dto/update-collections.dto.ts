import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsArray, IsOptional, IsString } from 'class-validator';

export class UpdateDictionaryDto {
  @ApiProperty({
    type: [String],
    example: ['Hallo', 'Danke'],
    description: 'Liste der gespeicherten Woerter',
  })
  @IsArray()
  @IsString({ each: true })
  dictionaryEntries!: string[];

  @ApiPropertyOptional({
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    description: 'Access token (alternativ zum Authorization Header)',
  })
  @IsOptional()
  @IsString()
  accessToken?: string;
}

export class UpdateFavoriteGesturesDto {
  @ApiProperty({
    type: [String],
    example: ['A', 'B', 'C'],
    description: 'Liste der favorisierten Gebaerden',
  })
  @IsArray()
  @IsString({ each: true })
  favoriteGestures!: string[];

  @ApiPropertyOptional({
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    description: 'Access token (alternativ zum Authorization Header)',
  })
  @IsOptional()
  @IsString()
  accessToken?: string;
}

export class UpdateBadgesDto {
  @ApiProperty({
    description: 'Badges Matrix: [badgeId, status(0|1), optional unlockedAt]',
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
  @IsArray()
  @IsArray({ each: true })
  badges!: number[][];

  @ApiPropertyOptional({
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    description: 'Access token (alternativ zum Authorization Header)',
  })
  @IsOptional()
  @IsString()
  accessToken?: string;
}
