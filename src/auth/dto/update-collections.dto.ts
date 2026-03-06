import { IsArray, IsOptional, IsString, IsNumber, Min, Max } from 'class-validator';

export class UpdateDictionaryDto {
  @IsArray()
  @IsString({ each: true })
  dictionaryEntries: string[];

  @IsOptional()
  @IsString()
  accessToken?: string;
}

export class UpdateFavoriteGesturesDto {
  @IsArray()
  @IsString({ each: true })
  favoriteGestures: string[];

  @IsOptional()
  @IsString()
  accessToken?: string;
}

export class UpdateBadgesDto {
  @IsArray()
  @IsArray({ each: true })
  badges: number[][];

  @IsOptional()
  @IsString()
  accessToken?: string;
}
