import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class SignResponseDto {
  @ApiProperty({ description: 'ID der Gebärde' })
  id: string;

  @ApiProperty({ description: 'Name der Gebärde' })
  name: string;

  @ApiProperty({ description: 'URL zur GLB-Datei' })
  glbUrl: string;

  @ApiPropertyOptional({ description: 'Beschreibung' })
  description?: string;

  @ApiPropertyOptional({ description: 'Kategorie' })
  category?: string;

  @ApiProperty({ description: 'Benötigt Update' })
  needsUpdate: boolean;

  @ApiPropertyOptional({ description: 'ETag für Update-Erkennung' })
  eTag?: string;

  @ApiPropertyOptional({ description: 'Letzter Änderungsdatum der Datei' })
  lastModified?: Date;

  @ApiPropertyOptional({ description: 'Zeitpunkt der letzten Überprüfung' })
  lastChecked?: Date;

  @ApiProperty({ description: 'Erstellungsdatum' })
  createdAt: Date;

  @ApiProperty({ description: 'Letztes Update' })
  updatedAt: Date;
}
