# Use a lightweight Node.js Alpine image for a smaller container footprint
FROM node:20-alpine

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json first
# This leverages Docker's layer caching so dependencies aren't re-installed unless they change
COPY package*.json ./

# Install production dependencies only
# Using 'npm ci' ensures a clean, reproducible install based on the lockfile
RUN npm ci --omit=dev

# Copy the rest of the application source code
COPY . .

# Cloud Run sets the PORT environment variable (defaults to 8080)
# This EXPOSE instruction is mostly for documentation
EXPOSE 8080

# Command to run the application
# Ensure your package.json has a "start" script, or change this to ["node", "index.js"]
CMD ["npm", "start"]