import { Controller, Get, Header } from '@nestjs/common';

@Controller('legal')
export class LegalController {
  @Get('privacy')
  @Header('Content-Type', 'text/html; charset=utf-8')
  getPrivacy(): string {
    return `<!DOCTYPE html>
      <html lang="de">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Datenschutzerklärung - Signly</title>
      </head>
      <body>
        <h1>Datenschutzerklärung</h1>
        <p>Hier folgt die Datenschutzerklärung von Signly.</p>
      </body>
      </html>`;
  }

  @Get('terms')
  @Header('Content-Type', 'text/html; charset=utf-8')
  getTerms(): string {
    return `<!DOCTYPE html>
      <html lang="de">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Nutzungsbedingungen - Signly</title>
      </head>
      <body>
        <h1>Nutzungsbedingungen</h1>
        <p>Hier folgen die Nutzungsbedingungen von Signly.</p>
      </body>
      </html>`;
  }

  @Get('imprint')
  @Header('Content-Type', 'text/html; charset=utf-8')
  getImprint(): string {
    return `<!DOCTYPE html>
      <html lang="de">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Impressum - Signly</title>
      </head>
      <body>
        <h1>Impressum</h1>
        <p>Hier folgt das Impressum von Signly.</p>
      </body>
      </html>`;
  }
}
