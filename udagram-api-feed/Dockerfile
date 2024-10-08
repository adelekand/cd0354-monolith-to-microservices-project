FROM node:iron-alpine
# Create app directory
WORKDIR /usr/src/app
# Install app dependencies

COPY package*.json ./
RUN npm ci
# Bundle app source
COPY . .
CMD ["npm", "run", "prod"]
