# SMS Forwarder — Backend (single file)

Multi-user live backend: register/login, per-device API keys, ingest endpoint,
real-time dashboard (Socket.io), SQLite storage.

## Run
    npm install
    JWT_SECRET=your-long-secret npm start
    # http://localhost:3000

## Deploy (Railway)
- New project from this GitHub repo
- Variables: JWT_SECRET = (a long random string)
- Add a Volume mounted at /app (so data.db persists)
- Generate a public domain

## Phone app
Set the app's Webhook URL to:  https://YOUR-HOST/api/ingest
and send the device API key (X-API-Key header, or api_key in the JSON body).
