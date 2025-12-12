export function renderSuccessPageHtml(name: string) {
  const safeName = (name || '')
    .toString()
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  const baseUrl = 'https://backend.signly.at';
  const assetsBaseUrl = `${baseUrl}/email-assets`;

  return `
      <!DOCTYPE html>
      <html lang="de">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>E-Mail verifiziert - Signly</title>
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

          .brand-name {
            font-weight: 700;
            letter-spacing: 0.03em;
            font-size: 14px;
            text-transform: uppercase;
            color: var(--primary);
            margin-top: 10px;
          }

          .pill {
            font-size: 11px;
            padding: 4px 10px;
            border-radius: 999px;
            border: 1px solid rgba(15,23,42,0.08);
            background: rgba(255,255,255,0.8);
            color: var(--text-muted);
          }

          .hero {
            display: flex;
            flex-direction: row;
            align-items: center;
            gap: 16px;
            margin-top: 8px;
          }

          .hero-illustration {
            flex: 0 0 160px;
          }

          .hero-illustration img {
            display: block;
            max-width: 160px;
            width: 100%;
            height: auto;
          }

          .hero-copy {
            flex: 1;
            text-align: left;
          }
          .status-icon {
            width: 40px;
            height: 40px;
            border-radius: 999px;
            background: rgba(166, 249, 253, 0.6);
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 8px;
            border: 1px solid #3b82c4;
          }

          .status-icon::before {
            content: "";
            display: block;
            width: 10px;
            height: 18px;
            border-right: 3px solid #3b82c4;
            border-bottom: 3px solid #3b82c4;
            transform: rotate(45deg) translateY(-1px);
          }

          h1 {
            margin: 0 0 6px;
            font-size: 22px;
            color: var(--primary);
          }

          .subtitle {
            margin: 0 0 10px;
            font-size: 14px;
            color: var(--text-muted);
          }

          .username {
            margin: 4px 0 16px;
            font-size: 16px;
            font-weight: 600;
            color: var(--text-main);
          }

          .hint {
            font-size: 13px;
            color: var(--text-muted);
            margin: 0 0 4px;
          }

          .secondary {
            font-size: 11px;
            color: #9ca3af;
            margin: 10px 0 0;
          }

          #confetti-canvas {
            position: fixed;
            inset: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 999;
          }

          @media (max-width: 520px) {
            body {
              padding: 16px;
            }

            .card {
              padding: 22px 18px 18px;
            }

            .hero {
              flex-direction: column;
              text-align: center;
            }

            .hero-copy {
              text-align: center;
            }

            .card-header {
              flex-direction: row;
            }
          }
        </style>
      </head>
      <body>
        <canvas id="confetti-canvas"></canvas>

        <main class="card" role="main" aria-label="Bestätigung deiner E-Mail-Adresse">
          <div class="card-inner">
            <header class="card-header">
              <div class="logo">
                <img
                  src="https://storage.googleapis.com/signlydaten/schlange/Logo.png"
                  alt="Signly Logo"
                  style="height: 36px; width: auto;"
                  loading="eager"
                />
                <span class="brand-name">ignly</span>
              </div>
              <div class="pill">E-Mail bestätigt</div>
            </header>

            <section class="hero">
              <div class="hero-illustration" aria-hidden="true">
                <img
                  src="https://storage.googleapis.com/signlydaten/schlange/Maskotchen.png"
                  alt="Signly Maskottchen"
                  style="max-width: 160px; width: 100%; height: auto; display: block;"
                  loading="eager"
                />
              </div>
              <div class="hero-copy">
                <div class="status-icon" aria-hidden="true"></div>
                <h1>E-Mail erfolgreich verifiziert</h1>
                <p class="subtitle">
                  Deine E-Mail-Adresse wurde bestätigt und dein Signly-Account ist jetzt erstellt.
                </p>
                <p class="username">
                  Willkommen bei Signly, ${safeName}!
                </p>
                <p class="hint">
                  Du kannst dieses Fenster jetzt schließen, merke dir nur deine Anmeldedaten.
                </p>
              </div>
            </section>
          </div>
        </main>

        <script>
          (function () {
            const canvas = document.getElementById('confetti-canvas');
            if (!canvas || !canvas.getContext) return;

            const ctx = canvas.getContext('2d');
            let width = window.innerWidth;
            let height = window.innerHeight;
            canvas.width = width;
            canvas.height = height;

            window.addEventListener('resize', () => {
              width = window.innerWidth;
              height = window.innerHeight;
              canvas.width = width;
              canvas.height = height;
            });

            const colors = ['#a6f9fd', '#3b82c4', '#073b4c', '#facc15'];
            const confettiCount = 120;
            const gravity = 0.25;
            const terminalVelocity = 4;
            const drag = 0.02;

            const randomRange = (min, max) => Math.random() * (max - min) + min;

            const confetti = [];
            for (let i = 0; i < confettiCount; i++) {
              confetti.push({
                color: colors[Math.floor(Math.random() * colors.length)],
                dimensions: {
                  x: randomRange(6, 10),
                  y: randomRange(8, 14),
                },
                position: {
                  x: Math.random() * width,
                  y: randomRange(-height, 0),
                },
                rotation: randomRange(0, 2 * Math.PI),
                velocity: {
                  x: randomRange(-2.5, 2.5),
                  y: randomRange(1, 2.5),
                },
                opacity: 1,
                decay: randomRange(0.003, 0.008),
              });
            }

            const duration = 6000;
            const startTime = performance.now();

            const render = (time) => {
              const elapsed = time - startTime;
              ctx.clearRect(0, 0, width, height);

              confetti.forEach((confetto) => {
                if (confetto.opacity <= 0) return;

                confetto.velocity.x -= confetto.velocity.x * drag;
                confetto.velocity.y = Math.min(
                  confetto.velocity.y + gravity,
                  terminalVelocity
                );

                confetto.position.x += confetto.velocity.x;
                confetto.position.y += confetto.velocity.y;

                confetto.opacity -= confetto.decay;

                if (confetto.position.y >= height) {
                  confetto.position.y = height + 20;
                }
                if (confetto.position.x > width) confetto.position.x = 0;
                if (confetto.position.x < 0) confetto.position.x = width;

                confetto.rotation += confetto.velocity.x * 0.02;

                ctx.save();
                ctx.globalAlpha = Math.max(confetto.opacity, 0);
                ctx.translate(confetto.position.x, confetto.position.y);
                ctx.rotate(confetto.rotation);
                ctx.fillStyle = confetto.color;
                ctx.fillRect(
                  -confetto.dimensions.x / 2,
                  -confetto.dimensions.y / 2,
                  confetto.dimensions.x,
                  confetto.dimensions.y
                );
                ctx.restore();
              });

              const allInvisible = confetti.every((c) => c.opacity <= 0);
              if (elapsed < duration && !allInvisible) {
                requestAnimationFrame(render);
              } else {
                ctx.clearRect(0, 0, width, height);
                if (canvas && canvas.parentNode) {
                  canvas.parentNode.removeChild(canvas);
                }
              }
            };

            requestAnimationFrame(render);
          })();
        </script>
      </body>
      </html>
    `;
}

export function renderExpiredPageHtml() {
  const baseUrl = 'https://backend.signly.at';
  const assetsBaseUrl = `${baseUrl}/email-assets`;

  return `
      <!DOCTYPE html>
      <html lang="de">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Link abgelaufen - Signly</title>
        <style>
          :root {
            --bg-page: #fff5f5;
            --bg-card: #ffffff;
            --danger: #e53935;
            --text-main: #1f2933;
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
            margin: 0;
            min-height: 100vh;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
            background: radial-gradient(circle at top left, #ffe2e2 0, #fff5f5 45%, #ffffff 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
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
            background: radial-gradient(circle at top right, rgba(239,68,68,0.12), transparent 60%);
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

          .brand-name {
            font-weight: 700;
            letter-spacing: 0.03em;
            font-size: 14px;
            text-transform: uppercase;
            color: var(--text-main);
            margin-top: 10px;
          }

          .pill {
            font-size: 11px;
            padding: 4px 10px;
            border-radius: 999px;
            border: 1px solid rgba(248,113,113,0.5);
            background: rgba(254,242,242,0.9);
            color: #b91c1c;
          }

          .hero {
            display: flex;
            flex-direction: row;
            align-items: center;
            gap: 16px;
            margin-top: 8px;
          }

          .hero-illustration {
            flex: 0 0 160px;
          }

          .hero-illustration img {
            display: block;
            max-width: 160px;
            width: 100%;
            height: auto;
          }

          .hero-copy {
            flex: 1;
            text-align: left;
          }

          .status-icon {
            width: 40px;
            height: 40px;
            border-radius: 999px;
            background: #fee2e2;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 10px;
            border: 1px solid rgba(248,113,113,0.7);
            position: relative;
          }

          .status-icon::before,
          .status-icon::after {
            content: "";
            position: absolute;
            width: 14px;
            height: 2px;
            background: var(--danger);
            border-radius: 999px;
          }

          .status-icon::before {
            transform: rotate(45deg);
          }

          .status-icon::after {
            transform: rotate(-45deg);
          }

          h1 {
            margin: 0 0 6px;
            font-size: 22px;
            color: var(--text-main);
          }

          .subtitle {
            margin: 0 0 10px;
            font-size: 14px;
            color: var(--text-muted);
          }

          .hint {
            color: #9ca3af;
            font-size: 12px;
            margin: 0;
          }

          @media (max-width: 520px) {
            body {
              padding: 16px;
            }

            .card {
              padding: 22px 18px 18px;
            }

            .hero {
              flex-direction: column;
              text-align: center;
            }

            .hero-copy {
              text-align: center;
            }

            .card-header {
              flex-direction: row;
            }
          }
        </style>
      </head>
      <body>
        <main class="card" role="main" aria-label="Hinweis: Bestätigungslink abgelaufen">
          <div class="card-inner">
            <header class="card-header">
              <div class="logo">
                <img
                  src="https://storage.googleapis.com/signlydaten/schlange/Logo.png"
                  alt="Signly Logo"
                  style="height: 36px; width: auto;"
                  loading="eager"
                />
                <span class="brand-name">ignly</span>
              </div>
              <div class="pill">Link abgelaufen</div>
            </header>

            <section class="hero">
              <div class="hero-illustration" aria-hidden="true">
                <img
                  src="https://storage.googleapis.com/signlydaten/schlange/SchlangeBoese.png"
                  alt="Signly Maskottchen"
                  style="max-width: 160px; width: 100%; height: auto; display: block;"
                  loading="eager"
                />
              </div>
              <div class="hero-copy">
                <div class="status-icon" aria-hidden="true"></div>
                <h1>Dieser Bestätigungslink ist nicht mehr gültig</h1>
                <p class="subtitle">
                  Der Link ist abgelaufen oder wurde bereits verwendet.
                  Bitte fordere einen neuen Bestätigungslink an, um deine E-Mail-Adresse zu verifizieren.
                </p>
              </div>
            </section>
          </div>
        </main>
      </body>
      </html>
    `;
}
