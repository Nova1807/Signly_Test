import { IsArray, IsOptional, IsString } from 'class-validator';

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
