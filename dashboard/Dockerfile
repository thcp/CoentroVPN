FROM node:22.15.0-bullseye

WORKDIR /app

COPY . .

RUN npm install && npm run build

CMD ["npm", "run", "preview"]