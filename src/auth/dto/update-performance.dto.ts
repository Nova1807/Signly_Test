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

export class UpdateLessonPerformanceDto {
  @IsNumber()
  lessonId: number;

  @IsNumber()
  @Min(0)
  @Max(100)
  percentage: number;

  @IsOptional()
  @IsString()
  accessToken?: string;
}

class LessonPerformanceEntryDto {
  @IsNumber()
  lessonId: number;

  @IsNumber()
  @Min(0)
  @Max(100)
  percentage: number;
}

export class UpdateLessonPerformanceMatrixDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => LessonPerformanceEntryDto)
  entries: LessonPerformanceEntryDto[];

  @IsOptional()
  @IsString()
  accessToken?: string;
}

export class UpdateTestPerformanceDto {
  @IsNumber()
  testId: number;

  @IsNumber()
  @Min(0)
  @Max(100)
  percentage: number;

  @IsOptional()
  @IsString()
  accessToken?: string;
}

class TestPerformanceEntryDto {
  @IsNumber()
  testId: number;

  @IsNumber()
  @Min(0)
  @Max(100)
  percentage: number;
}

export class UpdateTestPerformanceMatrixDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => TestPerformanceEntryDto)
  entries: TestPerformanceEntryDto[];

  @IsOptional()
  @IsString()
  accessToken?: string;
}
