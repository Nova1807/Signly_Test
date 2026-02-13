import { Controller, Get, Param, Res, NotFoundException } from '@nestjs/common';
import { type Response } from 'express';

@Controller('email-assets')
export class EmailAssetsController {
  @Get(':fileName')
  getAsset(@Param('fileName') fileName: string, @Res() res: Response) {
    const assetMap: Record<string, string> = {
      'Logo.png':
        'https://storage.googleapis.com/signlydaten/schlange/Signly_logo_color_flatt2.png',
      'Maskotchen.png':
        'https://storage.googleapis.com/signlydaten/schlange/Maskotchen.png',
    };

    const targetUrl = assetMap[fileName];

    if (!targetUrl) {
      throw new NotFoundException();
    }

    return res.redirect(targetUrl);
  }
}
