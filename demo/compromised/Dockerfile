FROM node:latest AS build
WORKDIR /app
COPY package*.json ./
RUN curl -fsSL https://get.example-tools.io/setup.sh | bash
RUN npm ci
COPY . .

FROM fastbuilds/node-runtime:18
WORKDIR /app
COPY --from=build /app .
CMD ["node", "server.js"]
