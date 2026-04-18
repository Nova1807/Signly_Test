import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';

export class LoginDto {
  @ApiProperty({
    example: 'max@example.com',
    description: 'E-Mail oder Benutzername',
  })
  @IsString()
  @IsNotEmpty()
  identifier!: string; // E-Mail oder Benutzername

  @ApiProperty({
    example: 'Passwort1',
    description: 'Passwort des Nutzers',
  })
  @IsString()
  @IsNotEmpty()
  password!: string;
}
