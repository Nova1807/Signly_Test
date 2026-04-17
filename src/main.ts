import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';
import * as express from 'express';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  app.use(express.urlencoded({ extended: true }));
  app.use(express.json());

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

  app.useStaticAssets(join(__dirname, '..', 'dist', 'Gebärden'), {
    prefix: '/gebarden',
  });

  const config = new DocumentBuilder()
    .setTitle('Signly API')
    .setDescription('API documentation for Signly backend')
    .setVersion('1.0')
    .build();

  const documentFactory = () => SwaggerModule.createDocument(app, config);

  SwaggerModule.setup('api', app, documentFactory, {
    jsonDocumentUrl: 'api-json',
  });

  await app.listen(process.env.PORT || 8080, '0.0.0.0');
}
bootstrap();