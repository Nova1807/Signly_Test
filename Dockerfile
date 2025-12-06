FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
# ➜ Bilder aus src in dist/auth/Bilder im finalen Image legen
COPY --from=builder /app/src/auth/Bilder ./dist/auth/Bilder
EXPOSE 8080
CMD ["node", "dist/main"]
