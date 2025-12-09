import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  app.use((req, res, next) => {
    console.log('REQ', req.method, req.url, new Date().toISOString());
    next();
  });

  // Hier liegen deine GLBs nach dem Build:
  app.useStaticAssets(join(__dirname, '..', 'dist', 'Gebärden'), {
    prefix: '/gebarden',
  });

  await app.listen(process.env.PORT || 8080, '0.0.0.0');
}
bootstrap();
