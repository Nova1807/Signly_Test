import { Controller, Get, Header } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiProduces, ApiTags } from '@nestjs/swagger';

@ApiTags('legal')
@Controller('legal')
export class LegalController {
  private readonly supportEmail = 'support@signly.at';
  private readonly logoUrl = 'https://backend.signly.at/email-assets/Logo.png';

  private pageShell(params: {
    title: string;
    pill: string;
    ariaLabel: string;
    subtitle: string;
    body: string;
  }): string {
    const { title, pill, ariaLabel, subtitle, body } = params;

    return `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${this.escapeHtml(title)} - Signly</title>
  <style>
    :root {
      --bg-page: #f4fbff;
      --bg-card: #ffffff;
      --primary: #073b4c;
      --text-main: #0b2135;
      --text-muted: #4a5568;
      --border-soft: rgba(15, 23, 42, 0.08);
      --link: #0b6b84;
    }

    * {
      box-sizing: border-box;
    }

    html, body {
      margin: 0;
      padding: 0;
      width: 100%;
      min-height: 100%;
    }

    body {
      min-height: 100vh;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
      background: radial-gradient(circle at top left, #e0f7ff 0, #f4fbff 45%, #ffffff 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      color: var(--text-main);
    }

    .card {
      width: 100%;
      max-width: 920px;
      background: var(--bg-card);
      border-radius: 20px;
      box-shadow: 0 18px 45px rgba(15, 23, 42, 0.18);
      padding: 32px 24px 24px;
      position: relative;
      overflow: hidden;
    }

    .card::before {
      content: '';
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
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 24px;
    }

    .logo img {
      display: block;
      height: 88px;
      width: auto;
    }

    .pill {
      font-size: 11px;
      padding: 4px 10px;
      border-radius: 999px;
      border: 1px solid rgba(15,23,42,0.08);
      background: rgba(255,255,255,0.8);
      color: var(--text-muted);
      white-space: nowrap;
    }

    .hero {
      display: flex;
      align-items: center;
      gap: 18px;
      margin-bottom: 24px;
    }

    .hero-copy {
      flex: 1;
    }

    h1 {
      margin: 0 0 8px;
      font-size: 28px;
      color: var(--primary);
    }

    .subtitle {
      margin: 0;
      font-size: 14px;
      color: var(--text-muted);
      max-width: 60ch;
      line-height: 1.65;
    }

    .content {
      display: grid;
      gap: 18px;
    }

    .section {
      background: rgba(255,255,255,0.72);
      border: 1px solid var(--border-soft);
      border-radius: 16px;
      padding: 18px 16px;
    }

    .section h2 {
      margin: 0 0 10px;
      font-size: 18px;
      color: var(--primary);
    }

    .section p,
    .section li {
      font-size: 14px;
      line-height: 1.65;
      color: var(--text-main);
    }

    .section p {
      margin: 0 0 10px;
    }

    .section p:last-child {
      margin-bottom: 0;
    }

    .section ul {
      margin: 0;
      padding-left: 18px;
    }

    .section li + li {
      margin-top: 6px;
    }

    a {
      color: var(--link);
      text-decoration: none;
    }

    a:hover {
      text-decoration: underline;
    }

    .note {
      font-size: 12px;
      color: #9ca3af;
      margin-top: 18px;
    }

    @media (max-width: 720px) {
      body {
        padding: 16px;
        align-items: flex-start;
      }

      .card {
        padding: 24px 18px 18px;
      }

      .logo img {
        height: 76px;
      }
    }
  </style>
</head>
<body>
  <main class="card" role="main" aria-label="${this.escapeHtml(ariaLabel)}">
    <div class="card-inner">
      <header class="card-header">
        <div class="logo">
          <img src="${this.escapeHtml(this.logoUrl)}" alt="Signly Logo" loading="eager" />
        </div>
        <div class="pill">${this.escapeHtml(pill)}</div>
      </header>

      <section class="hero">
        <div class="hero-copy">
          <h1>${this.escapeHtml(title)}</h1>
          <p class="subtitle">${subtitle}</p>
        </div>
      </section>

      <section class="content">
        ${body}
      </section>

      <p class="note">Stand: 16.04.2026</p>
    </div>
  </main>
</body>
</html>`;
  }

  private escapeHtml(value: string): string {
    return value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  @Get('privacy')
  @Header('Content-Type', 'text/html; charset=utf-8')
  @ApiOperation({ summary: 'Datenschutzerklaerung als HTML' })
  @ApiProduces('text/html')
  @ApiOkResponse({ description: 'HTML page', type: String })
  getPrivacy(): string {
    return this.pageShell({
      title: 'Datenschutzerklärung',
      pill: 'Datenschutz',
      ariaLabel: 'Datenschutzerklärung von Signly',
      subtitle:
        'Hier erfährst du, welche personenbezogenen Daten im Rahmen der Nutzung von Signly verarbeitet werden und zu welchen Zwecken dies geschieht.',
      body: `
        <div class="section">
          <h2>1. Verantwortliche</h2>
          <p>
            Erik Hauer<br />
            Linzer Straße 456<br />
            E-Mail: <a href="mailto:${this.supportEmail}">${this.supportEmail}</a>
          </p>
          <p>
            Victoria Kovacic<br />
            E-Mail: <a href="mailto:${this.supportEmail}">${this.supportEmail}</a>
          </p>
          <p>Signly ist derzeit ein Projekt im Rahmen einer Diplomarbeit und noch kein eingetragenes Unternehmen.</p>
        </div>

        <div class="section">
          <h2>2. Verarbeitete Daten</h2>
          <p>Im Rahmen der Nutzung von Signly können insbesondere folgende personenbezogene Daten verarbeitet werden:</p>
          <ul>
            <li>E-Mail-Adresse</li>
            <li>Benutzername</li>
            <li>Profilbild</li>
            <li>Authentifizierungsdaten</li>
          </ul>
        </div>

        <div class="section">
          <h2>3. Zweck der Datenverarbeitung</h2>
          <p>Die Verarbeitung der Daten erfolgt ausschließlich zur Bereitstellung und technischen Nutzung von Signly.</p>
          <p>
            Dies betrifft insbesondere die Registrierung und Anmeldung von Nutzerinnen und Nutzern,
            die Verwaltung von Benutzerkonten, die Speicherung und Anzeige von Profildaten sowie
            die Sicherstellung der technischen Funktionalität der Anwendung.
          </p>
        </div>

        <div class="section">
          <h2>4. Eingesetzte Dienste</h2>
          <p>Für den Betrieb von Signly werden externe technische Dienste verwendet.</p>
          <p>
            Google Firestore wird zur Speicherung von Anwendungsdaten verwendet.
            Google Cloud Storage wird zur Speicherung von Profilbildern verwendet.
          </p>
        </div>

        <div class="section">
          <h2>5. Passwörter und Sicherheit</h2>
          <p>
            Passwörter dienen ausschließlich der Authentifizierung.
            Sie dürfen nicht öffentlich angezeigt und nicht im Klartext gespeichert werden.
          </p>
        </div>

        <div class="section">
          <h2>6. Rechtsgrundlage</h2>
          <p>
            Die Verarbeitung personenbezogener Daten erfolgt zur Bereitstellung der App und ihrer Funktionen
            sowie gegebenenfalls auf Basis einer Einwilligung der Nutzerinnen und Nutzer.
          </p>
        </div>

        <div class="section">
          <h2>7. Speicherdauer</h2>
          <p>
            Personenbezogene Daten werden nur so lange gespeichert, wie dies für den Betrieb und die Bereitstellung
            von Signly erforderlich ist oder gesetzliche Pflichten bestehen.
          </p>
        </div>

        <div class="section">
          <h2>8. Rechte betroffener Personen</h2>
          <p>
            Betroffene Personen haben im Rahmen der gesetzlichen Bestimmungen insbesondere das Recht auf Auskunft,
            Berichtigung, Löschung, Einschränkung der Verarbeitung, Datenübertragbarkeit soweit anwendbar
            und Widerspruch soweit anwendbar.
          </p>
          <p>
            Anfragen dazu können an <a href="mailto:${this.supportEmail}">${this.supportEmail}</a> gerichtet werden.
          </p>
        </div>

        <div class="section">
          <h2>9. Änderungen</h2>
          <p>
            Diese Datenschutzerklärung kann angepasst werden, wenn sich technische, organisatorische oder rechtliche
            Rahmenbedingungen ändern.
          </p>
        </div>
      `,
    });
  }

  @Get('terms')
  @Header('Content-Type', 'text/html; charset=utf-8')
  @ApiOperation({ summary: 'Nutzungsbedingungen als HTML' })
  @ApiProduces('text/html')
  @ApiOkResponse({ description: 'HTML page', type: String })
  getTerms(): string {
    return this.pageShell({
      title: 'Nutzungsbedingungen',
      pill: 'Nutzungsbedingungen',
      ariaLabel: 'Nutzungsbedingungen von Signly',
      subtitle:
        'Diese Bedingungen regeln die Nutzung von Signly in der aktuellen Fassung als Projekt im Rahmen einer Diplomarbeit.',
      body: `
        <div class="section">
          <h2>1. Betreiber</h2>
          <p>
            Erik Hauer<br />
            Linzer Straße 456<br />
            E-Mail: <a href="mailto:${this.supportEmail}">${this.supportEmail}</a>
          </p>
          <p>
            Victoria Kovacic<br />
            E-Mail: <a href="mailto:${this.supportEmail}">${this.supportEmail}</a>
          </p>
        </div>

        <div class="section">
          <h2>2. Geltungsbereich</h2>
          <p>
            Signly ist derzeit ein Projekt im Rahmen einer Diplomarbeit und noch kein eingetragenes Unternehmen.
            Die Anwendung richtet sich aktuell in erster Linie an Nutzerinnen und Nutzer in Österreich
            und bezieht sich derzeit auf Österreichische Gebärdensprache.
          </p>
        </div>

        <div class="section">
          <h2>3. Nutzung der Anwendung</h2>
          <p>
            Die Nutzung von Signly ist nur im Rahmen der bereitgestellten technischen und inhaltlichen Funktionen gestattet.
          </p>
          <p>
            Nutzerinnen und Nutzer verpflichten sich, bei der Registrierung richtige Angaben zu machen
            und ihre Zugangsdaten sorgfältig aufzubewahren.
          </p>
        </div>

        <div class="section">
          <h2>4. Benutzerkonto</h2>
          <p>
            Für bestimmte Funktionen kann eine Registrierung erforderlich sein.
            Es besteht kein Anspruch auf Einrichtung oder dauerhafte Verfügbarkeit eines Benutzerkontos.
          </p>
          <p>
            Die Betreiber behalten sich vor, Konten bei Missbrauch, falschen Angaben oder technischen
            beziehungsweise organisatorischen Erfordernissen einzuschränken oder zu löschen.
          </p>
        </div>

        <div class="section">
          <h2>5. Verfügbarkeit</h2>
          <p>
            Es besteht kein Anspruch auf ununterbrochene Verfügbarkeit der Anwendung.
            Wartungen, technische Störungen, Weiterentwicklungen oder Änderungen können jederzeit
            zu Einschränkungen oder Unterbrechungen führen.
          </p>
        </div>

        <div class="section">
          <h2>6. Inhalte und Rechte</h2>
          <p>
            Alle Inhalte, Strukturen, Texte, Gestaltungen und sonstigen Bestandteile von Signly unterliegen,
            soweit rechtlich möglich, den jeweiligen Rechten der Betreiber oder der jeweils berechtigten Personen.
          </p>
          <p>
            Ohne ausdrückliche Zustimmung dürfen Inhalte von Signly nicht kopiert, veröffentlicht,
            bearbeitet oder außerhalb der bestimmungsgemäßen Nutzung verwendet werden.
          </p>
        </div>

        <div class="section">
          <h2>7. Pflichten der Nutzerinnen und Nutzer</h2>
          <ul>
            <li>Keine missbräuchliche oder rechtswidrige Nutzung der Anwendung.</li>
            <li>Keine Beeinträchtigung des technischen Betriebs.</li>
            <li>Keine Verwendung fremder oder unzulässiger Inhalte.</li>
            <li>Sorgfältiger Umgang mit Zugangsdaten.</li>
          </ul>
        </div>

        <div class="section">
          <h2>8. Haftung</h2>
          <p>
            Signly wird nach aktuellem Stand als Schulprojekt und Entwicklungsprojekt bereitgestellt.
            Trotz sorgfältiger Arbeit kann keine Gewähr für dauerhafte Verfügbarkeit, Fehlerfreiheit,
            Vollständigkeit oder uneingeschränkte Eignung für bestimmte Zwecke übernommen werden.
          </p>
          <p>
            Soweit gesetzlich zulässig, ist die Haftung für leichte Fahrlässigkeit ausgeschlossen.
            Die Haftung für Vorsatz sowie für Personenschäden bleibt unberührt.
          </p>
        </div>

        <div class="section">
          <h2>9. Änderungen und Weiterentwicklung</h2>
          <p>
            Die Betreiber behalten sich vor, Funktionen, Inhalte und diese Nutzungsbedingungen jederzeit anzupassen,
            zu ergänzen oder teilweise einzustellen.
          </p>
        </div>

        <div class="section">
          <h2>10. Anwendbares Recht</h2>
          <p>
            Es gilt österreichisches Recht unter Ausschluss der Verweisungsnormen,
            soweit dem keine zwingenden gesetzlichen Bestimmungen entgegenstehen.
          </p>
        </div>

        <div class="section">
          <h2>11. Kontakt</h2>
          <p>
            Für Fragen zur Nutzung von Signly:<br />
            <a href="mailto:${this.supportEmail}">${this.supportEmail}</a>
          </p>
        </div>
      `,
    });
  }

  @Get('imprint')
  @Header('Content-Type', 'text/html; charset=utf-8')
  getImprint(): string {
    return this.pageShell({
      title: 'Impressum',
      pill: 'Impressum',
      ariaLabel: 'Impressum von Signly',
      subtitle:
        'Angaben zu den verantwortlichen Personen und zur aktuellen Einordnung von Signly als Projekt im Rahmen einer Diplomarbeit.',
      body: `
        <div class="section">
          <h2>Verantwortliche für den Inhalt</h2>
          <p>
            Erik Hauer<br />
            Linzer Straße 456<br />
            E-Mail: <a href="mailto:${this.supportEmail}">${this.supportEmail}</a>
          </p>
          <p>
            Victoria Kovacic<br />
            E-Mail: <a href="mailto:${this.supportEmail}">${this.supportEmail}</a>
          </p>
        </div>

        <div class="section">
          <h2>Projektstatus</h2>
          <p>Signly ist derzeit ein Schulprojekt im Rahmen einer Diplomarbeit und noch kein eingetragenes Unternehmen.</p>
        </div>

        <div class="section">
          <h2>Inhaltliche Ausrichtung</h2>
          <p>Signly ist eine Anwendung im Bereich der Österreichischen Gebärdensprache.</p>
        </div>

        <div class="section">
          <h2>Kontakt</h2>
          <p>E-Mail: <a href="mailto:${this.supportEmail}">${this.supportEmail}</a></p>
        </div>

        <div class="section">
          <h2>Haftung für Inhalte</h2>
          <p>
            Die Inhalte dieser Anwendung wurden mit größtmöglicher Sorgfalt erstellt.
            Dennoch kann keine Gewähr für die Richtigkeit, Vollständigkeit und Aktualität
            der bereitgestellten Inhalte übernommen werden.
          </p>
        </div>
      `,
    });
  }
}