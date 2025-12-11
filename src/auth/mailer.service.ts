import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerService {
  private readonly logger = new Logger(MailerService.name);

  async sendVerificationEmail(email: string, token: string, name?: string) {
    this.logger.log(`sendVerificationEmail start: email=${email}, name='${name || ''}'`);

    const encodedToken = encodeURIComponent(token);
    this.logger.log(`sendVerificationEmail: raw token=${token}`);
    this.logger.log(`sendVerificationEmail: encoded token=${encodedToken}`);

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
      pool: true,
      maxConnections: 1,
      tls: {
        rejectUnauthorized: false,
      },
    });

    const baseVerifyUrl = 'https://backend.signly.at/auth/verify';
    const verifyUrl = `${baseVerifyUrl}?token=${encodedToken}`;
    this.logger.log(`sendVerificationEmail: verify URL: ${verifyUrl}`);

    const baseUrl = 'https://backend.signly.at';
    const assetsBaseUrl = `${baseUrl}/email-assets`;

    const mailOptions = {
      from: `"Signly" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Bestätige deine E-Mail-Adresse für Signly',
      html: `
      <!DOCTYPE html>
      <html lang="de">
        <body style="margin:0; padding:0; background-color:#f4fbff;">
          <table width="100%" cellspacing="0" cellpadding="0" style="padding:24px 0;">
            <tr>
              <td align="center">
                <table width="100%" cellspacing="0" cellpadding="0" 
                       style="max-width:600px; background-color:#ffffff; border-radius:16px; 
                              box-shadow:0 10px 25px rgba(0,0,0,0.06); padding:24px 24px 28px;">

                  <tr>
                    <td align="left" style="padding-bottom:8px;">
                      <img src="${assetsBaseUrl}/Logo.png"
                           alt="Signly Logo"
                           width="64"
                           height="36"
                           style="display:block; height:auto;" />
                    </td>
                  </tr>

                  <tr>
                    <td align="center" style="padding-bottom:16px;">
                      <img src="${assetsBaseUrl}/Maskotchen.png"
                           alt="Signly Maskotchen"
                           width="240"
                           height="240"
                           style="display:block; height:auto;" />
                    </td>
                  </tr>

                  <tr>
                    <td align="center" 
                        style="font-family:Arial, sans-serif; padding:8px 16px 4px;">
                      <h1 style="margin:0; font-size:22px; color:#073b4c;">
                        Willkommen bei Signly${name ? ', ' + name : ''}!
                      </h1>
                    </td>
                  </tr>

                  <tr>
                    <td align="center" 
                        style="font-family:Arial, sans-serif; padding:8px 32px 16px;">
                      <p style="margin:0; font-size:14px; line-height:1.6; color:#4a5568;">
                        Fast geschafft! Bitte bestätige deine E-Mail-Adresse, 
                        damit dein Signly-Account aktiviert werden kann.
                      </p>
                    </td>
                  </tr>

                  <tr>
                    <td align="center" style="padding:20px 16px 4px;">
                      <a href="${verifyUrl}"
                         style="
                           display:inline-block;
                           background-color:#a6f9fd;
                           color:#0b2135;
                           font-family:Arial, sans-serif;
                           font-size:15px;
                           font-weight:bold;
                           text-decoration:none;
                           padding:12px 28px;
                           border-radius:999px;
                           border:1px solid #3b82c4;
                           box-shadow:0 4px 10px rgba(59,130,196,0.35);
                         ">
                        E-Mail-Adresse bestätigen
                      </a>
                    </td>
                  </tr>

                  <tr>
                    <td align="center" 
                        style="font-family:Arial, sans-serif; padding:12px 24px 16px;">
                      <p style="margin:0; font-size:12px; color:#718096;">
                        Der Bestätigungslink ist <strong>15 Minuten</strong> gültig.
                      </p>
                    </td>
                  </tr>

                  <tr>
                    <td style="font-family:Arial, sans-serif; padding:8px 24px 16px;">
                      <p style="margin:0 0 4px; font-size:12px; color:#4a5568;">
                        Falls der Button nicht funktioniert, kopiere diesen Link in deinen Browser:
                      </p>
                      <p style="margin:0; font-size:11px; color:#2d3748; word-break:break-all;">
                        ${verifyUrl}
                      </p>
                    </td>
                  </tr>

                  <tr>
                    <td style="font-family:Arial, sans-serif; padding:16px 24px 8px;">
                      <p style="margin:0; font-size:11px; color:#a0aec0;">
                        Wenn du dich nicht bei Signly registriert hast, 
                        kannst du diese E-Mail ignorieren.
                      </p>
                    </td>
                  </tr>

                  <tr>
                    <td align="center" 
                        style="font-family:Arial, sans-serif; padding:12px 16px 0; 
                               border-top:1px solid #e2e8f0;">
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
      </html>
      `,
      headers: {
        'X-Priority': '1',
        Importance: 'high',
      },
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      this.logger.log(`sendVerificationEmail: mail sent to ${email}, messageId: ${info.messageId}`);
      return info;
    } catch (error) {
      this.logger.error(`sendVerificationEmail ERROR: ${error?.message}`, error?.stack);
      throw error;
    }
  }
}
