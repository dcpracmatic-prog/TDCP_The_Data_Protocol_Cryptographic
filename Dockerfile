# TDCP Web — local/demo image (Oracle remains in-browser; not a prod security boundary)
FROM node:22-bookworm-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

ENV HOST=0.0.0.0
ENV PORT=8080
EXPOSE 8080

# Dev server for interactive demos. For static serve, build and use a separate stage.
CMD ["npm", "run", "dev"]
