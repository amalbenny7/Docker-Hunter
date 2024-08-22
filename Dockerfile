# Use the official Node.js image.
FROM node:16

# Set the working directory in the container.
WORKDIR /app

# Copy package.json and package-lock.json for both frontend and backend
COPY frontend/package*.json ./frontend/
COPY backend/package*.json ./backend/

# Install dependencies for frontend and backend
RUN cd backend && npm install

# Copy the rest of the application code
COPY . .


# Move the built frontend files to the backend public directory

RUN cp frontend/dist/* backend/public

# Set the working directory to backend and expose the port
WORKDIR /app/backend
EXPOSE 8080

# Start the backend server
CMD ["npm", "start"]
