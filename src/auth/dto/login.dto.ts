import { IsString, IsNotEmpty } from 'class-validator';

export class LoginDto {
  @IsString()
  @IsNotEmpty()
  identifier: string; // E-Mail oder Benutzername

  @IsString()
  @IsNotEmpty()
  password: string;
}
