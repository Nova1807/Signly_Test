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
  const userData = userDoc.data() as any;
  const name = (userData && (userData.name || userData.displayName)) || '';

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
      name,
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

  // Hinweis: Da diese Methode synchron ist, können wir hier nicht direkt Firestore abfragen.
  // Stattdessen wird der Name bereits im Token-Dokument gespeichert und später clientseitig angezeigt,
  // falls du ihn per separatem Endpoint nachladen möchtest.

  // Einfaches HTML-Formular, das POST /password-reset/confirm aufruft
    // Der Token wird in einem hidden input mitgeschickt
  const html = `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Passwort zurücksetzen – Signly</title>
  <style>
    :root {
      --bg-page: #f4fbff;
      --bg-card: #ffffff;
      --primary: #073b4c;
      --accent: #a6f9fd;
      --accent-border: #3b82c4;
      --text-main: #0b2135;
      --text-muted: #4a5568;
    }

    * {
      box-sizing: border-box;
    }

    html, body {
      margin: 0;
      padding: 0;
      width: 100%;
      height: 100%;
    }

    body {
      min-height: 100vh;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
      background: radial-gradient(circle at top left, #e0f7ff 0, #f4fbff 45%, #ffffff 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      color: var(--text-main);
    }

    .card {
      width: 100%;
      max-width: 520px;
      background: var(--bg-card);
      border-radius: 20px;
      box-shadow: 0 18px 45px rgba(15, 23, 42, 0.18);
      padding: 28px 24px 24px;
      position: relative;
      overflow: hidden;
    }

    .card::before {
      content: "";
      position: absolute;
      inset: 0;
      background: radial-gradient(circle at top right, rgba(166,249,253,0.55), transparent 60%);
      opacity: 0.85;
      pointer-events: none;
    }

    .card-inner {
      position: relative;
      z-index: 1;
    }

    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 12px;
    }

    .logo {
      display: flex;
      align-items: center;
      gap: 2px;
    }

    .logo img {
      display: block;
      height: 36px;
      width: auto;
    }

    .header-right {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .pill {
      font-size: 11px;
      padding: 4px 10px;
      border-radius: 999px;
      border: 1px solid rgba(15,23,42,0.08);
      background: rgba(255,255,255,0.8);
      color: var(--text-muted);
    }

    .app-icon {
      width: 32px;
      height: 32px;
      border-radius: 10px;
      border: 1px solid rgba(59,130,196,0.35);
      box-shadow: 0 8px 18px rgba(15,23,42,0.18);
      background: #ffffff;
      display: block;
    }

    .hero {
      margin-top: 8px;
    }

    h1 {
      margin: 4px 0 10px;
      font-size: 22px;
      color: var(--primary);
      text-align: left;
    }

    p {
      margin: 0 0 10px;
      font-size: 14px;
      color: var(--text-muted);
      text-align: left;
    }

    .user-line {
      font-size: 13px;
      color: var(--text-main);
      margin-bottom: 10px;
    }

    .rules {
      font-size: 12px;
      color: #64748b;
      margin: 0 0 14px;
      padding-left: 18px;
    }

    label {
      display: block;
      margin-bottom: 6px;
      font-size: 13px;
      color: var(--text-main);
      font-weight: 500;
    }

    .field {
      position: relative;
      margin-bottom: 10px;
    }

    .password-input {
      width: 100%;
      padding: 9px 35px 9px 11px;
      border-radius: 10px;
      border: 1px solid #cbd5f5;
      font-size: 14px;
      box-sizing: border-box;
      background-color: #ffffff;
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }

    .password-input:focus {
      outline: none;
      border-color: #1e40af;
      box-shadow: 0 0 0 1px rgba(37,99,235,0.25);
    }

    .toggle-eye {
      position: absolute;
      right: 8px;
      top: 50%;
      transform: translateY(-50%);
      border: none;
      background: transparent;
      cursor: pointer;
      padding: 0;
      width: 22px;
      height: 22px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #64748b;
    }

    .toggle-eye svg {
      width: 18px;
      height: 18px;
      display: block;
    }

    .toggle-eye:focus {
      outline: none;
    }

    .btn {
      margin-top: 16px;
      width: 100%;
      border: none;
      border-radius: 999px;
      background: #1e40af;
      color: #ffffff;
      font-weight: 600;
      font-size: 14px;
      padding: 10px 14px;
      cursor: pointer;
      box-shadow: 0 10px 22px rgba(30,64,175,0.45);
    }

    .btn:disabled {
      opacity: .7;
      cursor: default;
      box-shadow: none;
    }

    .hint {
      margin-top: 10px;
      font-size: 12px;
      color: #94a3b8;
      text-align: left;
    }

    .error {
      margin-top: 10px;
      font-size: 13px;
      color: #b91c1c;
      text-align: left;
      display: none;
    }

    .success {
      margin-top: 10px;
      font-size: 13px;
      color: #15803d;
      text-align: left;
      display: none;
    }

    @media (max-width: 520px) {
      body {
        padding: 16px;
      }

      .card {
        padding: 22px 18px 18px;
      }
    }
  </style>
</head>
<body>
  <main class="card" role="main" aria-label="Passwort für deinen Signly-Account zurücksetzen">
    <div class="card-inner">
      <header class="card-header">
        <div class="logo">
          <img
            src="https://storage.googleapis.com/signlydaten/schlange/Signly_logo_color_flatt2.png"
            alt="Signly Logo"
            style="height: 36px; width: auto;"
            loading="eager"
          />
        </div>
        <div class="header-right">
          <div class="pill">Passwort zurücksetzen</div>
          <img
            src="https://storage.googleapis.com/signlydaten/schlange/signly_App_Icon.png"
            alt="Signly App Icon"
            class="app-icon"
            loading="eager"
          />
        </div>
      </header>

      <section class="hero">
        <h1>Neues Passwort setzen</h1>
        <p>Bitte gib dein neues Passwort ein. Danach kannst du dich wieder bei Signly anmelden.</p>
        <p class="user-line">Dieses Passwort gilt für deinen Signly-Account.</p>
        <ul class="rules">
          <li>Mindestens 8 Zeichen</li>
          <li>Mindestens 1 Buchstabe</li>
          <li>Mindestens 1 Zahl</li>
        </ul>
        <form id="resetForm">
          <input type="hidden" name="token" value="${token}" />
          <label for="password">Neues Passwort</label>
          <div class="field">
            <input id="password" name="password" class="password-input" type="password" required minlength="8" />
            <button type="button" class="toggle-eye" data-target="password" aria-label="Passwort anzeigen">
              <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                <path fill="currentColor" d="M12 5C7 5 3.1 8.1 1.5 12c1.6 3.9 5.5 7 10.5 7s8.9-3.1 10.5-7C20.9 8.1 17 5 12 5zm0 11.5A4.5 4.5 0 1 1 12 8.5a4.5 4.5 0 0 1 0 9z"/>
                <circle cx="12" cy="12" r="2.5" fill="currentColor" />
              </svg>
            </button>
          </div>

          <label for="passwordConfirm">Neues Passwort bestätigen</label>
          <div class="field">
            <input id="passwordConfirm" name="passwordConfirm" class="password-input" type="password" required minlength="8" />
            <button type="button" class="toggle-eye" data-target="passwordConfirm" aria-label="Passwort anzeigen">
              <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                <path fill="currentColor" d="M12 5C7 5 3.1 8.1 1.5 12c1.6 3.9 5.5 7 10.5 7s8.9-3.1 10.5-7C20.9 8.1 17 5 12 5zm0 11.5A4.5 4.5 0 1 1 12 8.5a4.5 4.5 0 0 1 0 9z"/>
                <circle cx="12" cy="12" r="2.5" fill="currentColor" />
              </svg>
            </button>
          </div>
          <button class="btn" type="submit">Passwort speichern</button>
          <div id="error" class="error">Etwas ist schiefgelaufen. Bitte versuche es erneut.</div>
          <div id="success" class="success">Dein Passwort wurde gespeichert. Du kannst dieses Fenster schließen.</div>
          <div class="hint">Wenn der Link abgelaufen ist, fordere bitte ein neues Passwort an.</div>
        </form>
      </section>
    </div>
  </main>
  <script>
    const form = document.getElementById('resetForm');
    const errorDiv = document.getElementById('error');
    const successDiv = document.getElementById('success');
    const passwordInput = document.getElementById('password');
    const passwordConfirmInput = document.getElementById('passwordConfirm');

    function toggleVisibility(targetId) {
      const input = document.getElementById(targetId);
      if (!input) return;
      const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
      input.setAttribute('type', type);
    }

    document.querySelectorAll('.toggle-eye').forEach((btn) => {
      btn.addEventListener('click', () => {
        const target = btn.getAttribute('data-target');
        toggleVisibility(target);
      });
    });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      errorDiv.style.display = 'none';
      successDiv.style.display = 'none';

       const pwd = passwordInput.value || '';
       const pwd2 = passwordConfirmInput.value || '';

       // einfache Client-Validierung
       if (pwd.length < 8) {
         errorDiv.textContent = 'Das Passwort muss mindestens 8 Zeichen lang sein.';
         errorDiv.style.display = 'block';
         return;
       }

       if (!/[A-Za-z]/.test(pwd) || !/[0-9]/.test(pwd)) {
         errorDiv.textContent = 'Das Passwort muss mindestens einen Buchstaben und eine Zahl enthalten.';
         errorDiv.style.display = 'block';
         return;
       }

       if (pwd !== pwd2) {
         errorDiv.textContent = 'Die Passwörter stimmen nicht überein.';
         errorDiv.style.display = 'block';
         return;
       }

      const formData = new FormData(form);
      const payload = {
        token: formData.get('token'),
        password: pwd,
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

    // HTML-Erfolgseite zurückgeben, damit der User eine schöne Bestätigung sieht
    const successHtml = `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Passwort gespeichert – Signly</title>
  <style>
    body { font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#f4fbff; margin:0; padding:0; color:#0f172a; }
    .page { min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px 12px; }
    .card { background:#ffffff; border-radius:22px; max-width:420px; width:100%; padding:22px 24px 24px; box-shadow:0 14px 34px rgba(11,33,53,0.10); box-sizing:border-box; text-align:center; }
    h1 { margin:0 0 10px; font-size:22px; color:#0b2135; }
    p { margin:0 0 10px; font-size:14px; color:#3b4a5a; }
    .ok { margin-top:14px; font-size:13px; color:#15803d; font-weight:500; }
  </style>
</head>
<body>
  <div class="page">
    <div class="card">
      <h1>Passwort gespeichert</h1>
      <p>Dein neues Passwort wurde erfolgreich gespeichert.</p>
      <p class="ok">Du kannst dieses Fenster jetzt schließen und dich in der App mit deinem neuen Passwort anmelden.</p>
    </div>
  </div>
</body>
</html>`;

    return successHtml;
  }
}
