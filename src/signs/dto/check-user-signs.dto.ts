import { IsArray, IsString, IsOptional, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class UserSignCheckDto {
  @ApiProperty({
    description: 'ID der Gebärde auf dem Gerät des Users',
    example: '507f1f77bcf86cd799439011',
  })
  @IsString()
  signId: string;

  @ApiPropertyOptional({
    description: 'Lokales ETag der Gebärde auf dem Gerät',
    example: '"33a64df551425fcc55e4d42a148795d9f25f89d4"',
  })
  @IsOptional()
  @IsString()
  localETag?: string;

  @ApiPropertyOptional({
    description: 'Lokales Last-Modified Datum der Gebärde',
    example: '2026-05-15T10:30:00.000Z',
  })
  @IsOptional()
  @IsString()
  localLastModified?: string;
}

export class CheckUserSignsDto {
  @ApiProperty({
    description: 'Liste der Gebärden, die der User hat und prüfen möchte',
    type: [UserSignCheckDto],
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => UserSignCheckDto)
  signs: UserSignCheckDto[];
}
