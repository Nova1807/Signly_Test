import { Body, Controller, Get, Header, Post } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiProduces, ApiTags } from '@nestjs/swagger';
import * as nodemailer from 'nodemailer';

@ApiTags('legal')
@Controller('legal')
export class LegalController {
  private readonly supportEmail = 'support@signly.at';
  private readonly legalLastUpdated = '24.04.2026';
  private readonly logoUrl =
    'https://storage.googleapis.com/signlydaten/schlange/Signly_logo_color_flatt2.png';

  private createBrevoTransport() {
    const user = process.env.BREVO_SMTP_USER;
    const pass = process.env.BREVO_SMTP_KEY;

    if (!user || !pass) {
      throw new Error('Missing Brevo SMTP credentials');
    }

    return nodemailer.createTransport({
      host: 'smtp-relay.brevo.com',
      port: 587,
      secure: false,
      auth: { user, pass },
      requireTLS: true,
      pool: true,
      maxConnections: 1,
      tls: {
        rejectUnauthorized: false,
      },
    });
  }

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

      <p class="note">Stand: ${this.escapeHtml(this.legalLastUpdated)}</p>
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
            Österreich<br />
            E-Mail: <a href="mailto:${this.supportEmail}">${this.supportEmail}</a>
          </p>
          <p>
            Victoria Kovacic<br />
            E-Mail: <a href="mailto:${this.supportEmail}">${this.supportEmail}</a>
          </p>
          <p>
            Signly wird derzeit als Schul- und Diplomarbeitsprojekt mit inhaltlichem Bezug zu Österreichischer
            Gebärdensprache betrieben und ist nach aktuellem Stand kein im Firmenbuch eingetragenes Unternehmen.
          </p>
          <p>
            Eine gesetzliche Pflicht zur Benennung einer oder eines Datenschutzbeauftragten besteht nach aktuellem
            Projektstatus nicht.
          </p>
        </div>

        <div class="section">
          <h2>2. Verarbeitete Datenkategorien</h2>
          <p>Im Rahmen der Nutzung von Signly können insbesondere folgende personenbezogene Daten verarbeitet werden:</p>
          <ul>
            <li>E-Mail-Adresse</li>
            <li>Name und Benutzername</li>
            <li>Profilbild und sonstige freiwillige Profilangaben wie "About me"</li>
            <li>Passwort-Hash, E-Mail-Verifizierungsdaten sowie Passwort-Reset-Daten</li>
            <li>Authentifizierungs- und Sitzungsdaten, insbesondere Access- und Refresh-Token</li>
            <li>Technische Metadaten zur Nutzung der bereitgestellten Funktionen</li>
            <li>Lern-, Fortschritts-, Favoriten-, Wörterbuch- und Freundeslisten-bezogene Daten</li>
            <li>Daten, die im Rahmen von Google- oder Apple-Login von den jeweiligen Anbietern bereitgestellt werden</li>
            <li>Inhalte und Kontaktdaten aus Anfragen, die über das Kontaktformular übermittelt werden</li>
          </ul>
        </div>

        <div class="section">
          <h2>3. Zwecke der Verarbeitung</h2>
          <p>Die Verarbeitung erfolgt zur Bereitstellung, Absicherung und Weiterentwicklung von Signly.</p>
          <p>
            Dies umfasst insbesondere die Registrierung und Anmeldung, die Verwaltung von Benutzerkonten,
            die Zustellung von Verifizierungs- und Passwort-Reset-E-Mails, die Speicherung von Profil- und
            Lerndaten, die Bereitstellung sozialer Funktionen wie Freundschaften sowie die Missbrauchs-,
            Sicherheits- und Fehlervermeidung. Kontaktanfragen werden zur Bearbeitung der jeweiligen Anfrage verarbeitet.
          </p>
        </div>

        <div class="section">
          <h2>4. Rechtsgrundlagen</h2>
          <p>
            Soweit personenbezogene Daten zur Bereitstellung eines Benutzerkontos und der App-Funktionen verarbeitet
            werden, erfolgt dies auf Grundlage von Art. 6 Abs. 1 lit. b DSGVO.
          </p>
          <p>
            Soweit die Verarbeitung zur technischen Sicherheit, Missbrauchsprävention, Fehleranalyse oder zur
            stabilen Bereitstellung des Dienstes erforderlich ist, erfolgt sie auf Grundlage von Art. 6 Abs. 1 lit. f DSGVO.
          </p>
          <p>
            Soweit eine Einwilligung erforderlich ist, erfolgt die Verarbeitung auf Grundlage von Art. 6 Abs. 1 lit. a DSGVO.
            Gesetzliche Aufbewahrungs- oder Offenlegungspflichten werden gegebenenfalls auf Grundlage von Art. 6 Abs. 1 lit. c DSGVO erfüllt.
          </p>
        </div>

        <div class="section">
          <h2>5. Eingesetzte Dienste und Empfänger</h2>
          <p>Für den technischen Betrieb von Signly werden externe Dienstleister und Plattformen eingesetzt.</p>
          <ul>
            <li>Google Firebase bzw. Google Cloud, insbesondere Firestore und Cloud Storage, zur Speicherung von Anwendungs- und Mediendaten</li>
            <li>Google OAuth für die Anmeldung mit Google</li>
            <li>Apple Sign In für die Anmeldung mit Apple</li>
            <li>Google Cloud Vision SafeSearch zur Prüfung hochgeladener Avatare auf problematische Inhalte</li>
            <li>Brevo SMTP für den Versand von Verifizierungs- und Passwort-Reset-E-Mails</li>
          </ul>
          <p>
            Dabei kann es zu einer Verarbeitung in Staaten außerhalb des Europäischen Wirtschaftsraums kommen.
            In solchen Fällen erfolgt die Nutzung dieser Anbieter nur auf Grundlage der jeweils einschlägigen
            datenschutzrechtlichen Voraussetzungen, etwa Angemessenheitsbeschlüssen oder Standardvertragsklauseln.
          </p>
        </div>

        <div class="section">
          <h2>6. Speicherdauer</h2>
          <p>
            Personenbezogene Daten werden nur so lange gespeichert, wie dies für die jeweiligen Zwecke erforderlich ist.
          </p>
          <ul>
            <li>Bestandsdaten des Benutzerkontos grundsätzlich bis zur Löschung des Accounts</li>
            <li>E-Mail-Verifizierungsdaten derzeit bis zu 15 Minuten</li>
            <li>Passwort-Reset-Daten derzeit bis zu 1 Stunde</li>
            <li>Refresh-Tokens derzeit bis zu 3 Tage</li>
            <li>Profilbilder bis zur Löschung durch die Nutzerin oder den Nutzer beziehungsweise bis zur Account-Löschung</li>
            <li>Kontaktanfragen grundsätzlich nur so lange, wie dies zur Bearbeitung und Dokumentation der Anfrage erforderlich ist</li>
          </ul>
          <p>
            Soweit gesetzliche Aufbewahrungspflichten bestehen oder Ansprüche geltend gemacht, ausgeübt oder verteidigt
            werden müssen, kann eine darüber hinausgehende Speicherung erforderlich sein.
          </p>
        </div>

        <div class="section">
          <h2>7. Datensicherheit</h2>
          <p>
            Signly trifft angemessene technische und organisatorische Maßnahmen, um personenbezogene Daten vor
            Verlust, Missbrauch und unbefugtem Zugriff zu schützen. Passwörter werden nach aktuellem Systemstand
            nicht im Klartext gespeichert.
          </p>
        </div>

        <div class="section">
          <h2>8. Rechte betroffener Personen</h2>
          <p>
            Betroffene Personen haben nach Maßgabe der DSGVO insbesondere das Recht auf Auskunft, Berichtigung,
            Löschung, Einschränkung der Verarbeitung, Datenübertragbarkeit, Widerspruch sowie auf Widerruf einer
            erteilten Einwilligung mit Wirkung für die Zukunft.
          </p>
          <p>
            Zur Ausübung dieser Rechte kann eine Nachricht an
            <a href="mailto:${this.supportEmail}">${this.supportEmail}</a> gesendet werden.
          </p>
          <p>
            Besteht die Ansicht, dass eine Datenverarbeitung gegen Datenschutzrecht verstößt, kann zudem eine Beschwerde
            bei der österreichischen Datenschutzbehörde eingebracht werden:
            <a href="https://www.dsb.gv.at" target="_blank" rel="noopener noreferrer">www.dsb.gv.at</a>.
          </p>
        </div>

        <div class="section">
          <h2>9. Keine ausschließlich automatisierten Entscheidungen</h2>
          <p>
            Eine ausschließlich automatisierte Entscheidungsfindung im Sinne von Art. 22 DSGVO findet nach aktuellem
            Stand nicht statt. Die Avatar-Prüfung dient der Inhaltsmoderation und technischen Missbrauchsprävention.
          </p>
        </div>

        <div class="section">
          <h2>10. Änderungen</h2>
          <p>
            Diese Datenschutzerklärung kann angepasst werden, wenn sich technische, organisatorische oder rechtliche
            Rahmenbedingungen ändern. Maßgeblich ist die jeweils auf dieser Seite veröffentlichte Fassung.
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
            Österreich<br />
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
          <p>Diese Nutzungsbedingungen gelten für die Nutzung der von Signly bereitgestellten App- und Backend-Funktionen.</p>
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
          <p>
            Die Nutzung zu rechtswidrigen Zwecken, zur Störung des Betriebs oder zur Umgehung technischer Schutzmaßnahmen
            ist unzulässig.
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
          <p>
            Nutzerinnen und Nutzer können ihr Konto im Rahmen der bereitgestellten Funktionen auch selbst löschen.
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
          <p>
            Inhalte, die von Nutzerinnen und Nutzern hochgeladen oder eingegeben werden, dürfen keine Rechte Dritter,
            keine gesetzlichen Vorschriften und keine Persönlichkeitsrechte verletzen.
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
            Die Haftung für Vorsatz, grobe Fahrlässigkeit, Personenschäden sowie nach zwingenden gesetzlichen Vorschriften
            bleibt unberührt.
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
          <p>
            Gegenüber Verbraucherinnen und Verbrauchern gelten zwingende Verbraucherschutzvorschriften des jeweiligen
            gewöhnlichen Aufenthalts unberührt fort, soweit sie anwendbar sind.
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
          <h2>1. Medieninhaberin, Herausgeberin und für den Inhalt verantwortlich</h2>
          <p>
            Erik Hauer<br />
            Linzer Straße 456<br />
            Österreich<br />
            E-Mail: <a href="mailto:${this.supportEmail}">${this.supportEmail}</a>
          </p>
          <p>
            Victoria Kovacic<br />
            E-Mail: <a href="mailto:${this.supportEmail}">${this.supportEmail}</a>
          </p>
        </div>

        <div class="section">
          <h2>2. Projektstatus</h2>
          <p>
            Signly ist derzeit ein Schulprojekt im Rahmen einer Diplomarbeit und nach aktuellem Stand kein im
            Firmenbuch eingetragenes Unternehmen.
          </p>
        </div>

        <div class="section">
          <h2>3. Unternehmens- bzw. Tätigkeitsgegenstand</h2>
          <p>Signly ist eine Lern- und Anwendungsplattform im Bereich der Österreichischen Gebärdensprache.</p>
        </div>

        <div class="section">
          <h2>4. Grundlegende Richtung des Mediums (Blattlinie)</h2>
          <p>
            Diese Website bzw. Anwendung dient der Information über Signly sowie der Bereitstellung digitaler Funktionen
            rund um Lernen, Profilverwaltung und Community-Funktionen im Bereich der Österreichischen Gebärdensprache.
          </p>
        </div>

        <div class="section">
          <h2>5. Kontakt</h2>
          <p>
            E-Mail: <a href="mailto:${this.supportEmail}">${this.supportEmail}</a><br />
            Kontaktformular: <a href="/legal/contact">/legal/contact</a>
          </p>
        </div>

        <div class="section">
          <h2>6. Haftung für Inhalte</h2>
          <p>
            Die Inhalte dieser Anwendung wurden mit größtmöglicher Sorgfalt erstellt.
            Dennoch kann keine Gewähr für die Richtigkeit, Vollständigkeit und Aktualität
            der bereitgestellten Inhalte übernommen werden.
          </p>
        </div>

        <div class="section">
          <h2>7. Hinweis zu weiteren Pflichtangaben</h2>
          <p>
            Angaben wie Firmenbuchnummer, Firmenbuchgericht, UID-Nummer, Aufsichtsbehörde oder Kammerzugehörigkeit
            werden derzeit nicht angeführt, soweit sie nach dem aktuellen Projektstatus von Signly nicht einschlägig sind.
          </p>
        </div>
      `,
    });
  }

  @Get('contact')
  @Header('Content-Type', 'text/html; charset=utf-8')
  getContact(): string {
    return this.pageShell({
      title: 'Kontakt',
      pill: 'Kontakt',
      ariaLabel: 'Kontaktformular von Signly',
      subtitle:
        'Über dieses Formular kannst du Signly direkt kontaktieren. Die übermittelten Angaben werden ausschließlich zur Bearbeitung deiner Anfrage verwendet.',
      body: `
        <div class="section">
          <h2>Kontaktformular</h2>
          <form method="post" action="/legal/contact" style="display:grid; gap:12px;">
            <label style="display:grid; gap:6px;">
              <span>Name</span>
              <input name="name" type="text" maxlength="120" required
                style="padding:12px 14px; border:1px solid var(--border-soft); border-radius:12px; font:inherit;" />
            </label>
            <label style="display:grid; gap:6px;">
              <span>E-Mail</span>
              <input name="email" type="email" maxlength="190" required
                style="padding:12px 14px; border:1px solid var(--border-soft); border-radius:12px; font:inherit;" />
            </label>
            <label style="display:grid; gap:6px;">
              <span>Nachricht</span>
              <textarea name="message" rows="7" maxlength="4000" required
                style="padding:12px 14px; border:1px solid var(--border-soft); border-radius:12px; font:inherit; resize:vertical;"></textarea>
            </label>
            <button type="submit"
              style="width:max-content; padding:12px 18px; border:0; border-radius:12px; background:#0b6b84; color:#fff; font:inherit; cursor:pointer;">
              Nachricht senden
            </button>
          </form>
        </div>
      `,
    });
  }

  @Post('contact')
  @Header('Content-Type', 'text/html; charset=utf-8')
  async submitContact(
    @Body('name') name: string,
    @Body('email') email: string,
    @Body('message') message: string,
  ): Promise<string> {
    const safeName = (name || '').trim().slice(0, 120);
    const safeEmail = (email || '').trim().slice(0, 190);
    const safeMessage = (message || '').trim().slice(0, 4000);

    if (!safeName || !safeEmail || !safeMessage) {
      return this.pageShell({
        title: 'Kontakt',
        pill: 'Kontakt',
        ariaLabel: 'Fehler im Kontaktformular von Signly',
        subtitle: 'Bitte fülle alle Felder aus und versuche es erneut.',
        body: `
          <div class="section">
            <h2>Unvollständige Anfrage</h2>
            <p>Alle Felder sind erforderlich.</p>
            <p><a href="/legal/contact">Zurück zum Kontaktformular</a></p>
          </div>
        `,
      });
    }

    try {
      const transporter = this.createBrevoTransport();
      await transporter.sendMail({
        from: `"Signly Kontaktformular" <${this.supportEmail}>`,
        replyTo: safeEmail,
        to: this.supportEmail,
        subject: `Kontaktanfrage Signly: ${safeName}`,
        text: [`Name: ${safeName}`, `E-Mail: ${safeEmail}`, '', safeMessage].join('\n'),
        html: `
          <p><strong>Name:</strong> ${this.escapeHtml(safeName)}</p>
          <p><strong>E-Mail:</strong> ${this.escapeHtml(safeEmail)}</p>
          <p><strong>Nachricht:</strong></p>
          <p>${this.escapeHtml(safeMessage).replace(/\n/g, '<br />')}</p>
        `,
      });

      return this.pageShell({
        title: 'Kontakt',
        pill: 'Kontakt',
        ariaLabel: 'Kontaktformular von Signly',
        subtitle: 'Deine Nachricht wurde versendet.',
        body: `
          <div class="section">
            <h2>Nachricht gesendet</h2>
            <p>Vielen Dank. Deine Anfrage wurde an ${this.escapeHtml(this.supportEmail)} übermittelt.</p>
            <p><a href="/legal/imprint">Zurück zum Impressum</a></p>
          </div>
        `,
      });
    } catch {
      return this.pageShell({
        title: 'Kontakt',
        pill: 'Kontakt',
        ariaLabel: 'Fehler beim Kontaktformular von Signly',
        subtitle: 'Die Nachricht konnte derzeit nicht versendet werden.',
        body: `
          <div class="section">
            <h2>Versand fehlgeschlagen</h2>
            <p>
              Bitte versuche es später erneut oder schreibe direkt an
              <a href="mailto:${this.supportEmail}">${this.supportEmail}</a>.
            </p>
            <p><a href="/legal/contact">Zurück zum Kontaktformular</a></p>
          </div>
        `,
      });
    }
  }
}
