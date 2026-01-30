import { BadRequestException, Injectable, Logger, Inject } from '@nestjs/common';
import * as admin from 'firebase-admin';
import * as bcrypt from 'bcrypt';
import { MailerService } from '../auth/mailer.service';

@Injectable()
export class PasswordResetService {
  private readonly logger = new Logger(PasswordResetService.name);

  constructor(
    // FIREBASE_APP wird bereits im Projekt verwendet, wir gehen von derselben Injection aus
    @Inject('FIREBASE_APP') private readonly firebaseApp: admin.app.App,
    private readonly mailerService: MailerService,
  ) {}

  // 1) Neuen Reset-Token erzeugen und Mail versenden
  async requestPasswordReset(email: string) {
    if (!email) {
      throw new BadRequestException('Email ist erforderlich');
    }

    const firestore = this.firebaseApp.firestore();

    // User anhand der E-Mail finden
    const userQuery = await firestore
      .collection('users')
      .where('email', '==', email)
      .get();

    if (userQuery.empty) {
      // Keine Info leaken: gleiche Antwort wie erfolgreicher Fall
      this.logger.warn(`requestPasswordReset: unknown email ${email}`);
      return {
        success: true,
        message:
          'Wenn ein Account mit dieser E-Mail existiert, wurde eine Nachricht versendet.',
      };
    }

    const userDoc = userQuery.docs[0];
    const userId = userDoc.id;

    // Alte Tokens des Users entfernen
    const oldTokensSnapshot = await firestore
      .collection('passwordResets')
      .where('userId', '==', userId)
      .get();

    const batch = firestore.batch();
    oldTokensSnapshot.forEach((doc) => batch.delete(doc.ref));
    await batch.commit();

    // Neuen Token erstellen
    const token = require('crypto').randomBytes(32).toString('hex');
    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + 60 * 60 * 1000); // 1h

    await firestore.collection('passwordResets').doc(token).set({
      userId,
      email,
      createdAt: admin.firestore.Timestamp.fromDate(createdAt),
      expiresAt: admin.firestore.Timestamp.fromDate(expiresAt),
      used: false,
    });

    // Mail versenden
    await this.mailerService.sendPasswordResetEmail(email, token);

    return {
      success: true,
      message:
        'Wenn ein Account mit dieser E-Mail existiert, wurde eine Nachricht versendet.',
    };
  }

  // 2) HTML-Seite mit Formular zurückgeben
  getResetFormHtml(token: string) {
    if (!token) {
      throw new BadRequestException('Token fehlt');
    }

    // Einfaches HTML-Formular, das POST /password-reset/confirm aufruft
    // Der Token wird in einem hidden input mitgeschickt
    const html = `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Passwort zurücksetzen – Signly</title>
  <style>
    body { font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#f4fbff; margin:0; padding:0; }
    .page { min-height:100vh; display:flex; align-items:center; justify-content:center; padding:16px; }
    .card { background:#ffffff; border-radius:16px; max-width:420px; width:100%; padding:24px 22px 20px; box-shadow:0 12px 30px rgba(15,23,42,0.18); }
    h1 { margin:0 0 12px; font-size:22px; color:#0f172a; text-align:center; }
    p { margin:0 0 18px; font-size:14px; color:#475569; text-align:center; }
    label { display:block; margin-bottom:6px; font-size:13px; color:#0f172a; font-weight:500; }
    input[type="password"] { width:100%; padding:10px 11px; border-radius:10px; border:1px solid #cbd5f5; font-size:14px; box-sizing:border-box; }
    input[type="password"]:focus { outline:none; border-color:#1e40af; box-shadow:0 0 0 1px rgba(37,99,235,0.25); }
    .btn { margin-top:16px; width:100%; border:none; border-radius:999px; background:#1e40af; color:#ffffff; font-weight:600; font-size:14px; padding:10px 14px; cursor:pointer; box-shadow:0 10px 22px rgba(30,64,175,0.45); }
    .btn:disabled { opacity:.7; cursor:default; box-shadow:none; }
    .hint { margin-top:12px; font-size:12px; color:#94a3b8; text-align:center; }
    .error { margin-top:12px; font-size:13px; color:#b91c1c; text-align:center; display:none; }
    .success { margin-top:12px; font-size:13px; color:#15803d; text-align:center; display:none; }
  </style>
</head>
<body>
  <div class="page">
    <div class="card">
      <h1>Neues Passwort setzen</h1>
      <p>Bitte gib dein neues Passwort ein. Danach kannst du dich wieder bei Signly anmelden.</p>
      <form id="resetForm">
        <input type="hidden" name="token" value="${token}" />
        <label for="password">Neues Passwort</label>
        <input id="password" name="password" type="password" required minlength="6" />
        <button class="btn" type="submit">Passwort speichern</button>
        <div id="error" class="error">Etwas ist schiefgelaufen. Bitte versuche es erneut.</div>
        <div id="success" class="success">Dein Passwort wurde gespeichert. Du kannst dieses Fenster schließen.</div>
        <div class="hint">Wenn der Link abgelaufen ist, fordere bitte ein neues Passwort an.</div>
      </form>
    </div>
  </div>
  <script>
    const form = document.getElementById('resetForm');
    const errorDiv = document.getElementById('error');
    const successDiv = document.getElementById('success');
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      errorDiv.style.display = 'none';
      successDiv.style.display = 'none';
      const formData = new FormData(form);
      const payload = {
        token: formData.get('token'),
        password: formData.get('password'),
      };
      try {
        const res = await fetch('/password-reset/confirm', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!res.ok) throw new Error('Request failed');
        const data = await res.json();
        if (data && data.success) {
          successDiv.style.display = 'block';
          form.querySelector('button').disabled = true;
          form.querySelector('input[type="password"]').disabled = true;
        } else {
          errorDiv.style.display = 'block';
        }
      } catch (err) {
        errorDiv.style.display = 'block';
      }
    });
  </script>
</body>
</html>`;

    return html;
  }

  // 3) Token prüfen, Passwort hashen und im User-Dokument speichern
  async resetPassword(token: string, newPassword: string) {
    if (!token || !newPassword) {
      throw new BadRequestException('Token und Passwort sind erforderlich');
    }

    const firestore = this.firebaseApp.firestore();
    const docRef = firestore.collection('passwordResets').doc(token);
    const doc = await docRef.get();

    if (!doc.exists) {
      throw new BadRequestException('Ungültiger oder abgelaufener Link');
    }

    const data = doc.data() as any;
    if (!data || data.used) {
      throw new BadRequestException('Ungültiger oder abgelaufener Link');
    }

    const now = new Date();
    const expiresAt = (data.expiresAt as admin.firestore.Timestamp).toDate();
    if (now > expiresAt) {
      throw new BadRequestException('Ungültiger oder abgelaufener Link');
    }

    const userId = data.userId as string;
    const userRef = firestore.collection('users').doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      throw new BadRequestException('Benutzer nicht gefunden');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await userRef.update({ password: hashedPassword });

    // Token als verwendet markieren (oder löschen)
    await docRef.update({ used: true });

    return { success: true, message: 'Passwort erfolgreich geändert.' };
  }
}
