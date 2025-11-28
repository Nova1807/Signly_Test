import {BadRequestException, Injectable, UnauthorizedException, Inject} from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import {SignupDto} from "./dto/signup.dto";
import * as admin from 'firebase-admin';
import * as bcrypt from 'bcrypt';
import {LoginDto} from "./dto/login.dto";
import { JwtService } from '@nestjs/jwt';
import {v4 as uuidv4} from 'uuid';
@Injectable()
export class AuthService {

    constructor(
        @Inject('FIREBASE_APP') private firebaseApp: admin.app.App,
        private jwtService: JwtService,
    ){}

 async signup(signupData: SignupDto) {

        const {email, password, name} = signupData;

        const firestore = this.firebaseApp.firestore();
        const userRef = firestore.collection('users').where('email', '==', email);
        const snapshot = await userRef.get();
        if (!snapshot.empty) {
            throw new BadRequestException('Diese Email hat bereits einen Account')
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await firestore.collection('users').add({
            name,
            email,
            password: hashedPassword,
        });
    }
    async login(credentials: LoginDto){
        const{ email, password} = credentials;
        const firestore = this.firebaseApp.firestore();
        const userRef = firestore.collection('users').where('email', '==', email);
        const snapshot = await userRef.get();
        if (snapshot.empty) {
            throw new UnauthorizedException('Wrong credentials');
        }
        const userDoc = snapshot.docs[0];
        const user = userDoc.data();

        const passwordMatch = await bcrypt.compare(password, user.password);
        if(!passwordMatch){
            throw new UnauthorizedException('Wrong credentials');
        }
        return this.generateUserToken(userDoc.id);
    }

    async refreshTokens(refreshToken: string){
        const firestore = this.firebaseApp.firestore();
        const tokenRef = firestore.collection('refreshTokens').where('token', '==', refreshToken).where('expiryDate', '>=', new Date());
        const snapshot = await tokenRef.get();
        if (snapshot.empty) {
            throw new UnauthorizedException();
        }
        const tokenDoc = snapshot.docs[0];
        const token = tokenDoc.data();
        return this.generateUserToken(token.userId);
    }



    async generateUserToken(userId){

        const accessToken = this.jwtService.sign({userId}, {expiresIn :'1h'});
        const refreshToken = uuidv4();

        await this.storeRefreshToken(refreshToken, userId);
        return{
            accessToken,
            refreshToken
        }
    }
    async storeRefreshToken(token: string, userId){
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate()+3);

        const firestore = this.firebaseApp.firestore();
        await firestore.collection('refreshTokens').add({token, userId, expiryDate});
    }
}
