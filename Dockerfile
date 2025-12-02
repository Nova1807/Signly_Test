# Build Stage (devDependencies)
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production Stage (nur prodDependencies)
FROM node:22-alpine AS production
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production --ignore-scripts && npm cache clean --force
COPY --from=builder /app/dist ./dist
# Firebase Service Account (falls benötigt)
COPY --chown=node:node ./service-account.json ./  
USER node
EXPOSE 8080
CMD ["node", "dist/main"]
