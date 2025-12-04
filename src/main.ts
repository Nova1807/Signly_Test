import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  // Request-Logging, um sicher zu sehen, dass Requests ankommen
  app.use((req, res, next) => {
    console.log(
      'REQ',
      req.method,
      req.url,
      new Date().toISOString(),
    );
    next();
  });

  await app.listen(process.env.PORT || 8080, '0.0.0.0');
}
bootstrap();
