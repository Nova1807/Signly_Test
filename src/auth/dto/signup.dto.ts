import {Prop} from "@nestjs/mongoose";
import {IsEmail, IsString, Matches, MinLength} from "class-validator";

export class SignupDto {
    @IsString()
    name: string;

    @IsEmail()
    email: string;

    @IsString()
    @MinLength(6)
    @Matches(/^(?=.*[0-9])/,{ message: 'Passwort muss mindestens eine Zahl enthalten'})
    password: string;
}