# Stage 1: Build the application using Node.js 20.1
FROM node:20.1 AS builder

# Set the working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy the rest of the application code
COPY . .

# Build the application (adjust this command based on your build process)
RUN npm run build

# Stage 2: Create the production image using Alpine
FROM alpine:3.18

# Install Node.js 20.1 in Alpine
RUN apk add --update --no-cache nodejs=~20.1 npm

# Set the working directory
WORKDIR /app

# Copy the built application from the builder stage
COPY --from=builder /app/dist ./dist

# Copy package.json and package-lock.json
COPY --from=builder /app/package*.json ./

# Install only production dependencies
RUN npm ci --only=production

# Expose the port your app runs on
EXPOSE 3000

# Command to run the application
CMD ["node", "dist/index.js"]