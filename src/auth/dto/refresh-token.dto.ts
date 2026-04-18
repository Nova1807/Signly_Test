import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class RefreshTokenDto {
    @ApiProperty({
        example: '7c2f4a9a-9dcb-4a60-8bd2-2cb4bfa2c1ae',
        description: 'Refresh-Token aus vorherigem Login',
    })
    @IsString()
    refreshToken: string;
}