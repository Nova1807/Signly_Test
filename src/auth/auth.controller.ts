import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { SignupDto } from "./dto/signup.dto";
import {LoginDto} from "./dto/login.dto";
import { RefreshTokenDto } from './dto/refresh-token.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {
    }

    @Post('signup')
    async signUp(@Body() signupData:SignupDto ){
        return this.authService.signup(signupData);
    }
    @Post('login')
    async login(@Body() credentials: LoginDto) {
        return this.authService.login(credentials);
    }
    @Post('refresh')
    async refreshtoken(@Body() refreshtokenDto: RefreshTokenDto){
        return this.authService.refreshTokens(refreshtokenDto.refreshToken);
    }
}