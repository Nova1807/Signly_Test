import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsNotEmpty, IsString } from 'class-validator';

export class SendFriendRequestDto {
  @ApiProperty({
    example: 'zielnutzer',
    description: 'Benutzername der Zielperson',
  })
  @IsString()
  @IsNotEmpty()
  targetUsername: string;
}

export class RespondFriendRequestDto {
  @ApiProperty({
    example: '9f2a5c3b-0a3f-4f8d-9b47-acde12ab34cd',
    description: 'ID der Freundschaftsanfrage',
  })
  @IsString()
  @IsNotEmpty()
  requestId: string;

  @ApiProperty({ example: true, description: 'Anfrage annehmen oder ablehnen' })
  @IsBoolean()
  accept: boolean;
}
