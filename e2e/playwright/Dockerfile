FROM mcr.microsoft.com/playwright:v1.58.0-jammy

WORKDIR /app

# Copy package files
COPY package.json ./

# Install dependencies
RUN npm install

# Ensure the Playwright chromium binary matches the npm-installed version.
# The base image bundles browsers at build time, but `npm install` may pull
# a newer @playwright/test that expects a different headless-shell binary
# path (e.g. chromium_headless_shell-1217). Reinstalling here aligns them.
RUN npx playwright install --with-deps chromium

# Copy source files
COPY . .

# Default command runs tests
CMD ["npm", "test"]
