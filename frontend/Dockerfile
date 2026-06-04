# Frontend dev container: serves Vite on :5173 with HMR.
# For a take-home this is fine; production would be `vite build` + nginx/static host.
FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY . .
EXPOSE 5173
# --host 0.0.0.0 so Vite is reachable from outside the container.
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
