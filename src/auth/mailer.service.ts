import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerService {
  private readonly logger = new Logger(MailerService.name);

  async sendVerificationEmail(email: string, token: string, name?: string) {
    this.logger.log(
      `sendVerificationEmail start: email=${email}, name='${name || ''}'`,
    );

    const encodedToken = encodeURIComponent(token);
    this.logger.log(`sendVerificationEmail: raw token=${token}`);
    this.logger.log(`sendVerificationEmail: encoded token=${encodedToken}`);

    const user = process.env.BREVO_SMTP_USER;
    const pass = process.env.BREVO_SMTP_KEY;

    if (!user || !pass) {
      this.logger.error(
        'Missing Brevo SMTP credentials. Set BREVO_SMTP_USER and BREVO_SMTP_KEY.',
      );
      throw new Error('Missing Brevo SMTP credentials');
    }

    const transporter = nodemailer.createTransport({
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

    const baseVerifyUrl = 'https://backend.signly.at/auth/verify';
    const verifyUrl = `${baseVerifyUrl}?token=${encodedToken}`;
    this.logger.log(`sendVerificationEmail: verify URL: ${verifyUrl}`);

    // Use image links 1:1 as requested
    const logoUrl =
      'https://storage.googleapis.com/signlydaten/schlange/Signly_logo_color_flatt2.png';
    const appIconUrl =
      'https://storage.googleapis.com/signlydaten/schlange/signly_App_Icon.png';
    const mascotUrl =
      'https://storage.googleapis.com/signlydaten/schlange/Schlange_mail.png';

    const subject = 'Bestätige deine E-Mail-Adresse für Signly';

    const text = [
      `Hallo${name ? ` ${name}` : ''},`,
      ``,
      `bitte bestätige deine E-Mail-Adresse, um deinen Signly-Account zu aktivieren.`,
      `Der Bestätigungslink ist 15 Minuten gültig.`,
      ``,
      `Link: ${verifyUrl}`,
      ``,
      `Wenn du dich nicht bei Signly registriert hast, kannst du diese E-Mail ignorieren.`,
      ``,
      `Signly Support: support@signly.at`,
    ].join('\n');

    const html = `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="x-apple-disable-message-reformatting" />
  <title>Signly – E-Mail bestätigen</title>
</head>

<body style="margin:0; padding:0; background-color:#f4fbff; font-family: Arial, sans-serif; color:#0b2135;">
  <!-- Preheader -->
  <div style="display:none; font-size:1px; line-height:1px; max-height:0; max-width:0; opacity:0; overflow:hidden;">
    Bitte bestätige deine E-Mail-Adresse, um deinen Signly-Account zu aktivieren. Link gültig für 15 Minuten.
  </div>

  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#f4fbff; padding:28px 0;">
    <tr>
      <td style="text-align:center; padding:0 12px;">

        <table role="presentation" width="600" cellspacing="0" cellpadding="0"
               style="width:100%; max-width:600px; background:#ffffff; border-radius:22px; overflow:hidden; box-shadow:0 14px 34px rgba(11,33,53,0.10); margin:0 auto;">

          <!-- Brand header (centered, bigger) -->
          <tr>
            <td style="padding:24px 22px 6px; text-align:center; background:#ffffff;">
              <img
                src="${logoUrl}"
                alt="Signly"
                width="190"
                style="display:block; height:auto; margin:0 auto;"
              />
            </td>
          </tr>

          <!-- Mascot hero (tinted card) -->
          <tr>
            <td style="padding:14px 22px 0; text-align:center; background:#ffffff;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
                     style="border-radius:16px; overflow:hidden;">
                <tr>
                  <td style="padding:16px 14px; text-align:center;">
                    <img
                      src="${mascotUrl}"
                      alt="Signly Maskotchen"
                      width="280"
                      style="display:block; height:auto; margin:0 auto;"
                    />
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Copy centered -->
          <tr>
            <td style="padding:16px 26px 0; text-align:center; background:#ffffff;">
              <h1 style="margin:0; font-size:22px; line-height:1.25; color:#0b2135;">
                E-Mail-Adresse bestätigen${name ? `, ${name}` : ``}
              </h1>
              <p style="margin:10px 0 0; font-size:14px; line-height:1.65; color:#3b4a5a;">
                Fast geschafft! Bitte bestätige deine E-Mail-Adresse, damit dein Signly Account aktiviert werden kann.
              </p>
            </td>
          </tr>

          <!-- CTA with glow (progressive enhancement) -->
          <tr>
            <td style="padding:18px 26px 0; text-align:center; background:#ffffff;">
              <!--[if mso]>
                <v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word"
                  href="${verifyUrl}" style="height:46px; v-text-anchor:middle; width:280px;" arcsize="25%"
                  strokecolor="#1e6fb8" fillcolor="#1e6fb8">
                  <w:anchorlock/>
                  <center style="color:#ffffff; font-family:Arial, sans-serif; font-size:15px; font-weight:bold;">
                    E-Mail bestätigen
                  </center>
                </v:roundrect>
              <![endif]-->
              <!--[if !mso]><!-- -->
              <a href="${verifyUrl}"
                 style="display:inline-block; background:#1e6fb8; color:#ffffff;
                        font-size:15px; font-weight:bold; text-decoration:none;
                        padding:14px 28px; border-radius:14px;
                        box-shadow:0 10px 26px rgba(30,111,184,0.45);">
                E-Mail bestätigen
              </a>
              <!--<![endif]-->

              <p style="margin:10px 0 0; font-size:12px; color:#64748b;">
                Der Link ist <strong>15 Minuten</strong> gültig.
              </p>
            </td>
          </tr>

          <!-- Safety note -->
          <tr>
            <td style="padding:14px 26px 22px; text-align:center; background:#ffffff;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
                     style="background:#e9fbff; border-radius:12px;">
                <tr>
                  <td style="padding:12px 12px; text-align:center;">
                    <p style="margin:0; font-size:12px; line-height:1.6; color:#64748b;">
                      Wenn du dich nicht bei Signly registriert hast, kannst du diese E-Mail ignorieren.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer (centered) -->
          <tr>
            <td style="border-top:1px solid #e8f1f8; padding:14px 26px 18px; text-align:center; background:#ffffff;">
              <p style="margin:0; font-size:11px; color:#94a3b8;">
                Support:
                <a href="mailto:support@signly.at" style="color:#1e6fb8; text-decoration:underline;">
                  support@signly.at
                </a>
              </p>
              <p style="margin:6px 0 0; font-size:11px; color:#94a3b8;">
                © ${new Date().getFullYear()} Signly. Alle Rechte vorbehalten.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

    const mailOptions = {
      from: `"Signly Support" <support@signly.at>`,
      replyTo: `"Signly Support" <support@signly.at>`,
      to: email,
      subject,
      text,
      html,
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      this.logger.log(
        `sendVerificationEmail: mail sent to ${email}, messageId: ${info.messageId}`,
      );
      return info;
    } catch (error) {
      this.logger.error(
        `sendVerificationEmail ERROR: ${error?.message}`,
        error?.stack,
      );
      throw error;
    }
  }

  async sendPasswordResetEmail(email: string, token: string) {
    this.logger.log(`sendPasswordResetEmail start: email=${email}`);

    const encodedToken = encodeURIComponent(token);

    const user = process.env.BREVO_SMTP_USER;
    const pass = process.env.BREVO_SMTP_KEY;

    if (!user || !pass) {
      this.logger.error(
        'Missing Brevo SMTP credentials. Set BREVO_SMTP_USER and BREVO_SMTP_KEY.',
      );
      throw new Error('Missing Brevo SMTP credentials');
    }

    const transporter = nodemailer.createTransport({
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

    const baseResetUrl = 'https://backend.signly.at/password-reset/form';
    const resetUrl = `${baseResetUrl}?token=${encodedToken}`;
    this.logger.log(`sendPasswordResetEmail: reset URL: ${resetUrl}`);

    // Gleiche Bild-Assets wie in der Verifizierungs-Mail
    const logoUrl =
      'https://storage.googleapis.com/signlydaten/schlange/Signly_logo_color_flatt2.png';
    const mascotUrl =
      'https://storage.googleapis.com/signlydaten/schlange/verwirrt_schlange.png';

    const subject = 'Passwort zurücksetzen für deinen Signly‑Account';

    const text = [
      `Hallo,`,
      ``,
      `du hast angefragt, dein Passwort bei Signly zurückzusetzen.`,
      `Wenn du das nicht warst, kannst du diese E-Mail ignorieren.`,
      ``,
      `Link zum Zurücksetzen (1 Stunde gültig):`,
      `${resetUrl}`,
    ].join('\n');

    const html = `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="x-apple-disable-message-reformatting" />
  <title>Signly – Passwort zurücksetzen</title>
</head>

<body style="margin:0; padding:0; background-color:#f4fbff; font-family: Arial, sans-serif; color:#0b2135;">
  <div style="display:none; font-size:1px; line-height:1px; max-height:0; max-width:0; opacity:0; overflow:hidden;">
    Setze dein Passwort für deinen Signly-Account zurück. Link 1 Stunde gültig.
  </div>

  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#f4fbff; padding:28px 0;">
    <tr>
      <td style="text-align:center; padding:0 12px;">

        <table role="presentation" width="600" cellspacing="0" cellpadding="0"
               style="width:100%; max-width:600px; background:#ffffff; border-radius:22px; overflow:hidden; box-shadow:0 14px 34px rgba(11,33,53,0.10); margin:0 auto;">

          <!-- Brand header -->
          <tr>
            <td style="padding:24px 22px 6px; text-align:center; background:#ffffff;">
              <img
                src="${logoUrl}"
                alt="Signly"
                width="190"
                style="display:block; height:auto; margin:0 auto;"
              />
            </td>
          </tr>

          <!-- Mascot hero -->
          <tr>
            <td style="padding:14px 22px 0; text-align:center; background:#ffffff;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
                     style="border-radius:16px; overflow:hidden;">
                <tr>
                  <td style="padding:16px 14px; text-align:center;">
                    <img
                      src="${mascotUrl}"
                      alt="Signly Maskotchen"
                      width="280"
                      style="display:block; height:auto; margin:0 auto;"
                    />
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Copy -->
          <tr>
            <td style="padding:16px 26px 0; text-align:center; background:#ffffff;">
              <h1 style="margin:0; font-size:22px; line-height:1.25; color:#0b2135;">
                Passwort zurücksetzen
              </h1>
              <p style="margin:10px 0 0; font-size:14px; line-height:1.65; color:#3b4a5a;">
                Setze hier ein neues Passwort für deinen Signly Account.
              </p>
            </td>
          </tr>

          <!-- CTA -->
          <tr>
            <td style="padding:18px 26px 0; text-align:center; background:#ffffff;">
              <a href="${resetUrl}"
                 style="display:inline-block; background:#1e6fb8; color:#ffffff;
                        font-size:15px; font-weight:bold; text-decoration:none;
                        padding:14px 28px; border-radius:14px;
                        box-shadow:0 10px 26px rgba(30,111,184,0.45);">
                Passwort zurücksetzen
              </a>
              <p style="margin:10px 0 0; font-size:12px; color:#64748b;">
                Falls der Button nicht funktioniert, kopiere diesen Link in deinen Browser:<br />
                <a href="${resetUrl}" style="color:#1e6fb8; word-break:break-all;">${resetUrl}</a>
              </p>
            </td>
          </tr>

          <!-- Safety note -->
          <tr>
            <td style="padding:14px 26px 22px; text-align:center; background:#ffffff;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
                     style="background:#e9fbff; border-radius:12px;">
                <tr>
                  <td style="padding:12px 12px; text-align:center;">
                    <p style="margin:0; font-size:12px; line-height:1.6; color:#64748b;">
                      Wenn du dein Passwort nicht zurücksetzen wolltest, kannst du diese E-Mail ignorieren.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="border-top:1px solid #e8f1f8; padding:14px 26px 18px; text-align:center; background:#ffffff;">
              <p style="margin:0; font-size:11px; color:#94a3b8;">
                Support:
                <a href="mailto:support@signly.at" style="color:#1e6fb8; text-decoration:underline;">
                  support@signly.at
                </a>
              </p>
              <p style="margin:6px 0 0; font-size:11px; color:#94a3b8;">
                © ${new Date().getFullYear()} Signly. Alle Rechte vorbehalten.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

    const mailOptions = {
      from: `"Signly Support" <support@signly.at>`,
      replyTo: `"Signly Support" <support@signly.at>`,
      to: email,
      subject,
      text,
      html,
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      this.logger.log(
        `sendPasswordResetEmail: mail sent to ${email}, messageId: ${info.messageId}`,
      );
      return info;
    } catch (error) {
      this.logger.error(
        `sendPasswordResetEmail ERROR: ${error?.message}`,
        error?.stack,
      );
      throw error;
    }
  }
}
