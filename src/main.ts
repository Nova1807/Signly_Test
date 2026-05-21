import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';
import * as express from 'express';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { timingSafeEqual } from 'crypto';

type SwaggerCredentialPair = {
  username: string;
  password: string;
};

function getSwaggerCredentialPairs(): SwaggerCredentialPair[] {
  const pairs: SwaggerCredentialPair[] = [];

  const legacyUsername = process.env.SWAGGER_USERNAME;
  const legacyPassword = process.env.SWAGGER_PASSWORD;
  if (legacyUsername && legacyPassword) {
    pairs.push({ username: legacyUsername, password: legacyPassword });
  }

  for (let index = 1; index <= 10; index += 1) {
    const username = process.env[`SWAGGER_USERNAME_${index}`];
    const password = process.env[`SWAGGER_PASSWORD_${index}`];

    if (username && password) {
      pairs.push({ username, password });
    }
  }

  return pairs;
}

function isValidSwaggerCredentials(authorizationHeader: string | undefined): boolean {
  const credentialPairs = getSwaggerCredentialPairs();

  if (!authorizationHeader?.startsWith('Basic ') || credentialPairs.length === 0) {
    return false;
  }

  const encodedCredentials = authorizationHeader.slice('Basic '.length).trim();

  let decodedCredentials: string;
  try {
    decodedCredentials = Buffer.from(encodedCredentials, 'base64').toString('utf8');
  } catch {
    return false;
  }

  const separatorIndex = decodedCredentials.indexOf(':');
  if (separatorIndex < 0) {
    return false;
  }

  const providedUsername = decodedCredentials.slice(0, separatorIndex);
  const providedPassword = decodedCredentials.slice(separatorIndex + 1);

  return credentialPairs.some(({ username, password }) => {
    if (providedUsername.length !== username.length || providedPassword.length !== password.length) {
      return false;
    }

    return (
      timingSafeEqual(Buffer.from(providedUsername), Buffer.from(username)) &&
      timingSafeEqual(Buffer.from(providedPassword), Buffer.from(password))
    );
  });
}

function swaggerBasicAuthMiddleware(req: express.Request, res: express.Response, next: express.NextFunction) {
  const credentialPairs = getSwaggerCredentialPairs();

  if (credentialPairs.length === 0) {
    console.error(
      'Swagger basic auth is not configured. Set SWAGGER_USERNAME/SWAGGER_PASSWORD or SWAGGER_USERNAME_N/SWAGGER_PASSWORD_N.',
    );
    res
      .status(500)
      .send(
        'Swagger basic auth is not configured. Set SWAGGER_USERNAME/SWAGGER_PASSWORD or SWAGGER_USERNAME_N/SWAGGER_PASSWORD_N.',
      );
    return;
  }

  if (!isValidSwaggerCredentials(req.headers.authorization)) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Swagger"');
    res.setHeader('Cache-Control', 'no-store');
    res.status(401).send('Authentication required');
    return;
  }

  next();
}

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

  app.use(/^\/api(?:\/.*)?$/, swaggerBasicAuthMiddleware);
  app.use(/^\/api-json(?:\/.*)?$/, swaggerBasicAuthMiddleware);

  app.useStaticAssets(join(__dirname, '..', 'dist', 'Gebärden'), {
    prefix: '/gebarden',
  });

  const config = new DocumentBuilder()
    .setTitle('Signly API')
    .setDescription('API documentation for Signly backend')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);

  SwaggerModule.setup('api', app, document, {
    jsonDocumentUrl: 'api-json',
  });

  await app.listen(process.env.PORT || 8080, '0.0.0.0');
}
bootstrap();