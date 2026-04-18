import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, MinLength, Matches } from 'class-validator';

export class PasswordResetRequestDto {
  @ApiProperty({
    example: 'max@example.com',
    description: 'E-Mail-Adresse fuer den Passwort-Reset',
  })
  @IsEmail()
  email: string;
}

export class PasswordResetConfirmDto {
  @ApiProperty({
    example: '9f2a5c3b0a3f4f8d9b47c0d1a2b3c4d5',
    description: 'Reset-Token aus der E-Mail',
  })
  @IsString()
  @IsNotEmpty()
  token: string;

  @ApiProperty({
    example: 'NeuesPasswort1',
    description: 'Neues Passwort (mindestens 8 Zeichen, Buchstabe + Zahl)',
  })
  @IsString()
  @MinLength(8)
  @Matches(/^(?=.*[A-Za-z])(?=.*[0-9])/, {
    message: 'Passwort muss mindestens einen Buchstaben und eine Zahl enthalten',
  })
  password: string;
}

export class PasswordResetResponseDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({
    example: 'Wenn ein Account mit dieser E-Mail existiert, wurde eine Nachricht versendet.',
  })
  message: string;
}
