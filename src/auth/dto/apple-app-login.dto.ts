import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class AppleAppLoginDto {
  @IsString()
  @IsNotEmpty()
  identityToken: string; // Raw id_token from ASAuthorizationAppleIDCredential

  @IsOptional()
  @IsString()
  authorizationCode?: string; // Provided for completeness if we need server-to-server token exchange later

  @IsOptional()
  @IsString()
  user?: string; // Optional JSON the iOS SDK returns on first login (matches Apple web payload)

  @IsOptional()
  @IsString()
  email?: string; // Fallback email if "user" field is not available anymore

  @IsOptional()
  @IsString()
  fullName?: string;

  @IsOptional()
  @IsString()
  firstName?: string;

  @IsOptional()
  @IsString()
  lastName?: string;
}
