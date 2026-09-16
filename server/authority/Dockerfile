# TDCP Authorization Authority (MVP durable stub — NOT HSM-backed)
FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ENV TDCP_AUTHORITY_PORT=8787
ENV TDCP_AUTHORITY_DATA_DIR=/data/authority
EXPOSE 8787
VOLUME ["/data/authority"]
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD node -e "fetch('http://127.0.0.1:8787/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "--experimental-strip-types", "server/authority/index.ts"]
