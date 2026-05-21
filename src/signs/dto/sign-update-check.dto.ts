import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class SignUpdateCheckDto {
  @ApiProperty({ description: 'ID der Gebärde' })
  signId: string;

  @ApiProperty({ description: 'Name der Gebärde' })
  name: string;

  @ApiProperty({ description: 'Hat ein Update' })
  hasUpdate: boolean;

  @ApiPropertyOptional({
    description: 'Servereigenes aktuelles ETag',
  })
  serverETag?: string;

  @ApiPropertyOptional({
    description: 'Servereigenes aktuelles Last-Modified',
  })
  serverLastModified?: Date;

  @ApiPropertyOptional({
    description: 'Warum hat es ein Update (ETag oder LastModified geändert)',
  })
  reason?: string;
}
