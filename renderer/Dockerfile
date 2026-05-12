# Headless Chromium renderer for GENESIS T6.
# Uses Playwright's official Node image which bundles Chromium + all deps.
FROM mcr.microsoft.com/playwright:v1.48.1-jammy

ENV NODE_ENV=production \
    PORT=3301

WORKDIR /app

COPY package.json /app/package.json
RUN npm install --omit=dev

COPY server.js /app/server.js

# Drop privileges — Playwright images include the `pwuser` account.
USER pwuser

EXPOSE 3301
CMD ["node", "/app/server.js"]
