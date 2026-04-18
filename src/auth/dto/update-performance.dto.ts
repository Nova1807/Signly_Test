import {
  IsNumber,
  Min,
  Max,
  IsOptional,
  IsString,
  IsArray,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateLessonPerformanceDto {
  @ApiProperty({ example: 12, description: 'ID der Lektion' })
  @IsNumber()
  lessonId: number;

  @ApiProperty({ example: 85, description: 'Fortschritt in Prozent' })
  @IsNumber()
  @Min(0)
  @Max(100)
  percentage: number;

  @ApiPropertyOptional({
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    description: 'Access token (alternativ zum Authorization Header)',
  })
  @IsOptional()
  @IsString()
  accessToken?: string;
}

class LessonPerformanceEntryDto {
  @ApiProperty({ example: 12 })
  @IsNumber()
  lessonId: number;

  @ApiProperty({ example: 85 })
  @IsNumber()
  @Min(0)
  @Max(100)
  percentage: number;
}

export class UpdateLessonPerformanceMatrixDto {
  @ApiProperty({
    type: [LessonPerformanceEntryDto],
    description: 'Liste der Lektionseintraege',
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => LessonPerformanceEntryDto)
  entries: LessonPerformanceEntryDto[];

  @ApiPropertyOptional({
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    description: 'Access token (alternativ zum Authorization Header)',
  })
  @IsOptional()
  @IsString()
  accessToken?: string;
}

export class UpdateTestPerformanceDto {
  @ApiProperty({ example: 5, description: 'ID des Tests' })
  @IsNumber()
  testId: number;

  @ApiProperty({ example: 92, description: 'Fortschritt in Prozent' })
  @IsNumber()
  @Min(0)
  @Max(100)
  percentage: number;

  @ApiPropertyOptional({
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    description: 'Access token (alternativ zum Authorization Header)',
  })
  @IsOptional()
  @IsString()
  accessToken?: string;
}

class TestPerformanceEntryDto {
  @ApiProperty({ example: 5 })
  @IsNumber()
  testId: number;

  @ApiProperty({ example: 92 })
  @IsNumber()
  @Min(0)
  @Max(100)
  percentage: number;
}

export class UpdateTestPerformanceMatrixDto {
  @ApiProperty({
    type: [TestPerformanceEntryDto],
    description: 'Liste der Testeintraege',
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => TestPerformanceEntryDto)
  entries: TestPerformanceEntryDto[];

  @ApiPropertyOptional({
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    description: 'Access token (alternativ zum Authorization Header)',
  })
  @IsOptional()
  @IsString()
  accessToken?: string;
}
