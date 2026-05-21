import {
  Controller,
  Get,
  Post,
  Param,
  Body,
  Query,
  HttpCode,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiQuery,
  ApiParam,
} from '@nestjs/swagger';
import { SignsService } from './signs.service';
import { SignResponseDto } from './dto/sign-response.dto';
import { CheckUserSignsDto } from './dto/check-user-signs.dto';
import { SignUpdateCheckDto } from './dto/sign-update-check.dto';

@ApiTags('Signs / Gebärden')
@Controller('signs')
export class SignsController {
  private readonly logger = new Logger(SignsController.name);

  constructor(private readonly signsService: SignsService) {}

  /**
   * Anfrage 1: Was für Gebärden haben wir alle
   * GET /signs - Alle Gebärden mit optionalem Filter
   */
  @Get()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Alle Gebärden abrufen',
    description:
      'Gibt eine Liste aller verfügbaren Gebärden zurück. Optional nach Kategorie filterbar.',
  })
  @ApiQuery({
    name: 'category',
    description: 'Optional: Filtere nach Kategorie',
    required: false,
    type: String,
  })
  @ApiResponse({
    status: 200,
    description: 'Liste aller Gebärden',
    type: [SignResponseDto],
  })
  async getAllSigns(@Query('category') category?: string): Promise<SignResponseDto[]> {
    this.logger.log(
      `Alle Gebärden abrufen${category ? ` (Kategorie: ${category})` : ''}`,
    );
    return this.signsService.getSigns(category);
  }

  /**
   * Anfrage 2: Gibt es Gebärden die ein Update brauchen
   * GET /signs/updates/needed - Gebärden mit Update-Bedarf
   */
  @Get('updates/needed')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Gebärden mit Update-Bedarf abrufen',
    description:
      'Gibt alle Gebärden zurück, die ein Update benötigen (basierend auf HTTP-Header-Änderungen).',
  })
  @ApiResponse({
    status: 200,
    description: 'Liste der Gebärden mit Update-Bedarf',
    type: [SignResponseDto],
  })
  async getSignsNeedingUpdate(): Promise<SignResponseDto[]> {
    this.logger.log('Gebärden mit Update-Bedarf abrufen');
    return this.signsService.getSignsNeedingUpdate();
  }

  /**
   * Prüfe alle Gebärden auf Updates (vorher)
   * POST /signs/updates/check - Aktualisiere den Update-Status aller Gebärden
   */
  @Post('updates/check')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Alle Gebärden auf Updates prüfen',
    description:
      'Prüft alle Gebärden in Google Cloud Storage auf Änderungen (via ETag und Last-Modified Header). Aktualisiert den Status automatisch.',
  })
  @ApiResponse({
    status: 200,
    description: 'Liste der Gebärden, die Updates haben',
    type: [SignResponseDto],
  })
  async checkAllSignsForUpdates(): Promise<SignResponseDto[]> {
    this.logger.log('Prüfe alle Gebärden auf Updates');
    return this.signsService.checkAllSignsForUpdates();
  }

  /**
   * Neue Anfrage: User schickt seine Gebärden mit lokalen Versionsinformationen
   * POST /signs/updates/check-my-signs - Prüfe ob User-seitige Gebärden Updates brauchen
   */
  @Post('updates/check-my-signs')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Prüfe ob deine Gebärden Updates brauchen',
    description:
      'Der User schickt seine lokal gespeicherten Gebärden mit deren ETags/LastModified Daten. Der Server prüft diese gegen die aktuellen Cloud-Versionen.',
  })
  @ApiResponse({
    status: 200,
    description: 'Liste mit Update-Status für jede Gebärde',
    type: [SignUpdateCheckDto],
  })
  async checkUserSigns(@Body() checkUserSignsDto: CheckUserSignsDto): Promise<SignUpdateCheckDto[]> {
    this.logger.log(`Prüfe ${checkUserSignsDto.signs.length} User-Gebärden auf Updates`);
    return this.signsService.checkUserSigns(checkUserSignsDto.signs);
  }

  /**
   * Anfrage 3: Schicke mir diese Gebärden
   * GET /signs/:id - Spezifische Gebärde
   */
  @Get(':id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Einzelne Gebärde abrufen',
    description:
      'Gibt eine spezifische Gebärde mit allen Metadaten zurück.',
  })
  @ApiParam({ name: 'id', description: 'ID der Gebärde' })
  @ApiResponse({
    status: 200,
    description: 'Die angeforderte Gebärde',
    type: SignResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Gebärde nicht gefunden' })
  async getSignById(@Param('id') id: string): Promise<SignResponseDto | null> {
    this.logger.log(`Gebärde ${id} abrufen`);
    return this.signsService.getSignById(id);
  }
}
