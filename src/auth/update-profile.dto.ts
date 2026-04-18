import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, Length } from 'class-validator';

export class UpdateProfileDto {
  @ApiPropertyOptional({
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    description: 'Access token (alternativ zum Authorization Header)',
  })
  @IsOptional()
  @IsString()
  accessToken?: string;  // Token im Body erlaubt

  @ApiPropertyOptional({
    example: 'NeuerName',
    minLength: 3,
    maxLength: 30,
  })
  @IsOptional()
  @IsString()
  @Length(3, 30)
  name?: string;

  @ApiPropertyOptional({
    example: 'Kurze Beschreibung zu mir',
    maxLength: 300,
  })
  @IsOptional()
  @IsString()
  @Length(0, 300)
  aboutMe?: string;
}
