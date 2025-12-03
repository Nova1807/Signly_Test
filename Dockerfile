# Build Stage
FROM node:22-alpine AS builder
WORKDIR /app

# Nur package-Dateien kopieren und Dependencies installieren
COPY package*.json ./
RUN npm ci

# Restlichen Code kopieren und bauen
COPY . .
RUN npm run build

# Production Stage (einfach: gleiches Image weiterverwenden)
FROM node:22-alpine
WORKDIR /app

# Nur das Nötigste aus dem Builder übernehmen
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist

# Firebase Service Account JSON ins Image kopieren
# Pfad anpassen, falls deine Datei woanders liegt
COPY src/firebase/signly-be33f-firebase-adminsdk-fbsvc-cd21369526.json /app/firebase-key.json

# Port für Cloud Run
EXPOSE 8080

# Startkommando
CMD ["node", "dist/main"]
