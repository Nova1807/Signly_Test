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
      secure: false, // STARTTLS on 587 is the recommended default for Brevo SMTP relay [web:57][web:60]
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
    const logoUrl = 'https://storage.googleapis.com/signlydaten/schlange/Logo.png';
    const appIconUrl =
      'https://storage.googleapis.com/signlydaten/schlange/signly_App_Icon.png';
    const mascotUrl =
      'https://storage.googleapis.com/signlydaten/schlange/Maskotchen.png';

    const subject = 'Signly: Bitte E-Mail bestätigen';

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
  <title>E-Mail bestätigen</title>
</head>

<body style="margin:0; padding:0; background-color:#f4fbff;">
  <!-- Preheader (Inbox preview) -->
  <div style="display:none; font-size:1px; line-height:1px; max-height:0; max-width:0; opacity:0; overflow:hidden;">
    Bestätige deine E-Mail-Adresse, um deinen Signly-Account zu aktivieren. Link ist 15 Minuten gültig.
  </div>

  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#f4fbff; padding:24px 0;">
    <tr>
      <td align="center" style="padding:0 12px;">
        <table role="presentation" width="600" cellspacing="0" cellpadding="0"
          style="width:100%; max-width:600px; background:#ffffff; border-radius:16px; overflow:hidden; box-shadow:0 10px 25px rgba(0,0,0,0.06);">

          <!-- Header -->
          <tr>
            <td style="padding:18px 18px 10px;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr>
                  <td align="left" valign="middle">
                    <img
                      src="${logoUrl}"
                      alt="Signly"
                      width="96"
                      style="display:block; height:auto;"
                    />
                  </td>
                  <td align="right" valign="middle">
                    <img
                      src="${appIconUrl}"
                      alt="Signly App Icon"
                      width="36"
                      height="36"
                      style="display:block; border-radius:10px; border:1px solid #e2e8f0; background:#ffffff;"
                    />
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:10px 22px 0; font-family:Arial, sans-serif; color:#0b2135;">
              <h1 style="margin:0; font-size:22px; line-height:1.25;">
                E-Mail-Adresse bestätigen${name ? `, ${name}` : ``}
              </h1>
              <p style="margin:10px 0 0; font-size:14px; line-height:1.6; color:#4a5568;">
                Bitte bestätige deine E-Mail-Adresse, um deinen Signly-Account zu aktivieren.
              </p>
            </td>
          </tr>

          <!-- Small mascot row (reduced, not hero) -->
          <tr>
            <td style="padding:14px 22px 0;">
              <table role="presentation" cellspacing="0" cellpadding="0">
                <tr>
                  <td valign="middle" style="padding-right:10px;">
                    <img
                      src="${mascotUrl}"
                      alt="Signly Maskotchen"
                      width="56"
                      height="56"
                      style="display:block; border-radius:14px;"
                    />
                  </td>
                  <td valign="middle" style="font-family:Arial, sans-serif; font-size:12px; line-height:1.5; color:#718096;">
                    Link gültig für <strong>15 Minuten</strong>.
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CTA (bulletproof button with VML for Outlook) -->
          <tr>
            <td align="center" style="padding:18px 22px 8px;">
              <!--[if mso]>
                <v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word"
                  href="${verifyUrl}" style="height:46px; v-text-anchor:middle; width:280px;" arcsize="50%"
                  strokecolor="#1e6fb8" fillcolor="#1e6fb8">
                  <w:anchorlock/>
                  <center style="color:#ffffff; font-family:Arial, sans-serif; font-size:15px; font-weight:bold;">
                    E-Mail bestätigen
                  </center>
                </v:roundrect>
              <![endif]-->
              <!--[if !mso]><!-- -->
              <a href="${verifyUrl}"
                 style="display:inline-block; background:#1e6fb8; color:#ffffff; font-family:Arial, sans-serif;
                        font-size:15px; font-weight:bold; text-decoration:none; padding:13px 26px; border-radius:999px;">
                E-Mail bestätigen
              </a>
              <!--<![endif]-->
            </td>
          </tr>

          <!-- Fallback link -->
          <tr>
            <td style="padding:8px 22px 0; font-family:Arial, sans-serif;">
              <p style="margin:0; font-size:12px; line-height:1.6; color:#718096;">
                Wenn der Button nicht funktioniert, öffne diesen Link:
              </p>
              <p style="margin:6px 0 0; font-size:12px; line-height:1.6; word-break:break-all;">
                <a href="${verifyUrl}" style="color:#1e6fb8; text-decoration:underline;">
                  ${verifyUrl}
                </a>
              </p>
            </td>
          </tr>

          <!-- Security note -->
          <tr>
            <td style="padding:14px 22px 18px; font-family:Arial, sans-serif;">
              <p style="margin:0; font-size:12px; line-height:1.6; color:#a0aec0;">
                Wenn du dich nicht bei Signly registriert hast, kannst du diese E-Mail ignorieren.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="border-top:1px solid #e2e8f0; padding:12px 22px 16px; font-family:Arial, sans-serif;">
              <p style="margin:0; font-size:11px; color:#a0aec0;">
                Signly Support · <a href="mailto:support@signly.at" style="color:#a0aec0; text-decoration:underline;">support@signly.at</a>
              </p>
              <p style="margin:6px 0 0; font-size:11px; color:#a0aec0;">
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
      text, // multipart/alternative via Nodemailer fields [web:50]
      html, // clear CTA + fallback link is standard for verification emails [web:38]
      headers: {
        // Avoid “high priority” for deliverability; keep transactional clean and standard [web:40]
      },
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
}
