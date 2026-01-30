import { Body, Controller, Get, Post, Query } from '@nestjs/common';
import { PasswordResetService } from './password-reset.service';

@Controller('password-reset')
export class PasswordResetController {
  constructor(private readonly passwordResetService: PasswordResetService) {}

  // 1) Endpoint: Frontend sendet nur E-Mail -> wir erzeugen Reset‑Token und schicken E-Mail
  @Post('request')
  async requestReset(@Body('email') email: string) {
    return this.passwordResetService.requestPasswordReset(email);
  }

  // 2) Endpoint: Klick aus E-Mail -> liefert einfache HTML-Seite mit Formular
  @Get('form')
  async showResetForm(@Query('token') token: string) {
    return this.passwordResetService.getResetFormHtml(token);
  }

  // 3) Endpoint: Formular submit (per POST aus dem HTML)
  @Post('confirm')
  async confirmReset(
    @Body('token') token: string,
    @Body('password') password: string,
  ) {
    return this.passwordResetService.resetPassword(token, password);
  }
}
