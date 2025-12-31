FROM node:20-slim

# Install qpdf and dependencies for canvas
RUN apt-get update && apt-get install -y \
    qpdf \
    libcairo2-dev \
    libpango1.0-dev \
    libjpeg-dev \
    libgif-dev \
    librsvg2-dev

# Create app directory
WORKDIR /usr/src/app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the code
COPY . .

# Expose port and start the app
EXPOSE 10000
CMD ["node", "index.js"]
