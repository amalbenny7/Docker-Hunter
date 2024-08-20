# Build stage
FROM node:14 as build
WORKDIR /app

# Copy package.json and package-lock.json if it exists
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy all the source files
COPY . .

# Run the build command to generate the production files
RUN npm run build

# Production stage
FROM nginx:alpine

# Copy the build output from the previous stage
COPY --from=build /app/dist /usr/share/nginx/html

# Expose port 80 to the outside world
EXPOSE 80

# Start Nginx server
CMD ["nginx", "-g", "daemon off;"]
