import { Controller, Get, Param, Res, NotFoundException } from '@nestjs/common';
import { ApiOperation, ApiParam, ApiResponse, ApiTags } from '@nestjs/swagger';
import { type Response } from 'express';

@ApiTags('email-assets')
@Controller('email-assets')
export class EmailAssetsController {
  @Get(':fileName')
  @ApiOperation({ summary: 'Redirect to email asset' })
  @ApiParam({
    name: 'fileName',
    example: 'Logo.png',
    description: 'Dateiname des Email-Assets',
  })
  @ApiResponse({ status: 302, description: 'Redirect to asset URL' })
  @ApiResponse({ status: 404, description: 'Asset not found' })
  getAsset(@Param('fileName') fileName: string, @Res() res: Response) {
    const assetMap: Record<string, string> = {
      'Logo.png':
        'https://storage.googleapis.com/signlydaten/schlange/Signly_logo_color_flatt2.png',
      'Maskotchen.png':
        'https://storage.googleapis.com/signlydaten/schlange/Maskotchen.png',
      'signly_App_Icon.png':
        'https://storage.googleapis.com/signlydaten/schlange/signly_App_Icon.png',
      'SchlangeBoese.png':
        'https://storage.googleapis.com/signlydaten/schlange/SchlangeBoese.png',
    };

    const targetUrl = assetMap[fileName];

    if (!targetUrl) {
      throw new NotFoundException();
    }

    return res.redirect(targetUrl);
  }
}
