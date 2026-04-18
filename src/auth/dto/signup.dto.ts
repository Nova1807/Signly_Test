import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, Matches, MinLength } from 'class-validator';

export class SignupDto {
    @ApiProperty({
        example: 'Max Mustermann',
        description: 'Anzeigename des neuen Nutzers',
    })
    @IsString()
    name: string;

    @ApiProperty({
        example: 'max@example.com',
        description: 'E-Mail-Adresse des Nutzers',
    })
    @IsEmail()
    email: string;

    @ApiProperty({
        example: 'Passwort1',
        description: 'Passwort mit mindestens 6 Zeichen und einer Zahl',
    })
    @IsString()
    @MinLength(6)
    @Matches(/^(?=.*[0-9])/, { message: 'Passwort muss mindestens eine Zahl enthalten' })
    password: string;
}