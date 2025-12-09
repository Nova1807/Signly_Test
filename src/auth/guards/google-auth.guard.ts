import { Injectable, Logger } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class GoogleAuthGuard extends AuthGuard('google') {
  private readonly logger = new Logger(GoogleAuthGuard.name);

  // Optionales Logging beim Start des Auth-Flows
  getAuthenticateOptions(): any {
    this.logger.log('Starting Google OAuth flow via GoogleAuthGuard');
    // Hier könnte man optional zusätzliche Optionen setzen (prompt, accessType, etc.)
    return {};
  }
}
