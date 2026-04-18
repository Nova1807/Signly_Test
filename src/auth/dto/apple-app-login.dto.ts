import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class AppleAppLoginDto {
  @ApiProperty({
    example: 'eyJraWQiOiJ...apple-id-token...'
  })
  @IsString()
  @IsNotEmpty()
  identityToken: string; // Raw id_token from ASAuthorizationAppleIDCredential

  @ApiPropertyOptional({
    example: 'cfcf9d98f2a94...',
    description: 'Authorization code for server-to-server exchange',
  })
  @IsOptional()
  @IsString()
  authorizationCode?: string; // Provided for completeness if we need server-to-server token exchange later

  @ApiPropertyOptional({
    example: '{"name":{"firstName":"Max","lastName":"Mustermann"}}',
    description: 'Optional Apple user payload (raw JSON string)',
  })
  @IsOptional()
  @IsString()
  user?: string; // Optional JSON the iOS SDK returns on first login (matches Apple web payload)

  @ApiPropertyOptional({
    example: 'max@example.com',
    description: 'Fallback email if user payload is unavailable',
  })
  @IsOptional()
  @IsString()
  email?: string; // Fallback email if "user" field is not available anymore

  @ApiPropertyOptional({ example: 'Max Mustermann' })
  @IsOptional()
  @IsString()
  fullName?: string;

  @ApiPropertyOptional({ example: 'Max' })
  @IsOptional()
  @IsString()
  firstName?: string;

  @ApiPropertyOptional({ example: 'Mustermann' })
  @IsOptional()
  @IsString()
  lastName?: string;
}
