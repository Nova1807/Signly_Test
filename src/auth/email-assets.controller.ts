import {
  Controller,
  Get,
  Param,
  Res,
  NotFoundException,
} from '@nestjs/common';
import { join } from 'path';
import { existsSync } from 'fs';
import { type Response } from 'express';

@Controller('email-assets')
export class EmailAssetsController {
  @Get(':fileName')
  getAsset(@Param('fileName') fileName: string, @Res() res: Response) {
    const allowedFiles = ['Logo.png', 'Maskotchen.png'];

    if (!allowedFiles.includes(fileName)) {
      throw new NotFoundException();
    }

    // Pfad relativ zu src/auth/Bilder
    const filePath = join(__dirname, 'Bilder', fileName);

    if (!existsSync(filePath)) {
      throw new NotFoundException();
    }

    return res.sendFile(filePath);
  }
}
