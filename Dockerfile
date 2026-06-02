FROM node:18-slim

# Install dependencies for Puppeteer
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    ca-certificates \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libgbm1 \
    libglib2.0-0 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libx11-xcb1 \
    libxcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libxss1 \
    libxtst6 \
    xdg-utils \
    --no-install-recommends

# Create app directory with proper permissions
WORKDIR /app

# Create auth directory with write permissions
RUN mkdir -p /app/auth && chmod -R 777 /app/auth

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy bot code
COPY bot.js ./

# Create non-root user and give ownership
RUN groupadd -r pptruser && useradd -r -g pptruser pptruser && \
    chown -R pptruser:pptruser /app

# Switch to non-root user
USER pptruser

# Start the bot
CMD ["node", "bot.js"]
