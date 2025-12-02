# Build Stage (devDependencies)
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production Stage (nur prodDependencies)

# Firebase Service Account (falls benötigt)
EXPOSE 8080
CMD ["node", "dist/main"]
