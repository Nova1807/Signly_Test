import { Body, Controller, Get, Post, Query } from '@nestjs/common';
import {
  ApiBody,
  ApiOkResponse,
  ApiOperation,
  ApiProduces,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { PasswordResetService } from './password-reset.service';
import {
  PasswordResetConfirmDto,
  PasswordResetRequestDto,
  PasswordResetResponseDto,
} from './dto/password-reset.dto';

@ApiTags('password-reset')
@Controller('password-reset')
export class PasswordResetController {
  constructor(private readonly passwordResetService: PasswordResetService) {}

  // 1) Endpoint: Frontend sendet nur E-Mail -> wir erzeugen Reset‑Token und schicken E-Mail
  @Post('request')
  @ApiOperation({ summary: 'Passwort-Reset anfordern' })
  @ApiBody({ type: PasswordResetRequestDto })
  @ApiOkResponse({
    description: 'Anfrage akzeptiert',
    type: PasswordResetResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Ungueltige E-Mail' })
  async requestReset(@Body() dto: PasswordResetRequestDto) {
    return this.passwordResetService.requestPasswordReset(dto.email);
  }

  // 2) Endpoint: Klick aus E-Mail -> liefert einfache HTML-Seite mit Formular
  @Get('form')
  @ApiOperation({ summary: 'Reset-Formular als HTML' })
  @ApiQuery({ name: 'token', required: true, example: 'abc123' })
  @ApiProduces('text/html')
  @ApiOkResponse({ description: 'HTML page', type: String })
  @ApiResponse({ status: 400, description: 'Token fehlt oder ist ungueltig' })
  async showResetForm(@Query('token') token: string) {
    return this.passwordResetService.getResetFormHtml(token);
  }

  // 3) Endpoint: Formular submit (per POST aus dem HTML)
  @Post('confirm')
  @ApiOperation({ summary: 'Neues Passwort speichern' })
  @ApiBody({ type: PasswordResetConfirmDto })
  @ApiOkResponse({
    description: 'Passwort gespeichert',
    type: PasswordResetResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Token oder Passwort ungueltig' })
  async confirmReset(@Body() dto: PasswordResetConfirmDto) {
    return this.passwordResetService.resetPassword(dto.token, dto.password);
  }
}
