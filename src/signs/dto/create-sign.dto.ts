import { IsString, IsUrl, IsOptional } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateSignDto {
  @ApiProperty({ description: 'Name der Gebärde' })
  @IsString()
  name: string;

  @ApiProperty({ description: 'URL zur GLB-Datei in Google Cloud Storage' })
  @IsUrl()
  glbUrl: string;

  @ApiPropertyOptional({ description: 'Beschreibung der Gebärde' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({ description: 'Kategorie der Gebärde' })
  @IsOptional()
  @IsString()
  category?: string;
}
