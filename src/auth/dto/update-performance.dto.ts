import { IsNumber, Min, Max, IsOptional, IsString } from 'class-validator';

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
