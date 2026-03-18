FROM node:20-alpine

# Create app directory
WORKDIR /app

# Install dependencies first (cached layer)
COPY package.json ./
RUN npm install --production

# Copy source
COPY server.js ./
COPY public/   ./public/

# Never run as root
USER node

EXPOSE 3000

CMD ["node", "server.js"]
