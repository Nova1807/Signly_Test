import { ApiProperty } from '@nestjs/swagger';

export class AvatarUploadDto {
  @ApiProperty({
    type: 'string',
    format: 'binary',
    description: 'Avatar-Datei (PNG, JPEG oder WEBP)',
  })
  avatar: string;
}
