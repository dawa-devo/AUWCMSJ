# Backend setup

The backend uses Prisma ORM with MySQL. From this directory:

1. Copy `.env.example` to `.env` and set `DATABASE_URL` to the MySQL connection URL, for example `mysql://USER:PASSWORD@localhost:3306/auwcmsj`.
2. Create the `auwcmsj` database in MySQL.
3. Run `npm install`. The `postinstall` script generates the Prisma client; you can also run `npm run db:generate` explicitly.
4. Run `npm run db:migrate -- --name init` to create the Prisma migration and tables.
5. Set `ADMIN_ID` and `ADMIN_PASSWORD` in `.env`, then start the API with `node server.js`. Use a unique admin ID and a strong password (at least 8 characters with letters and numbers; 16 or more characters is recommended). The password is stored as a bcrypt hash.

At startup (and on the first API request in serverless deployments), the backend creates an active `admin` account only if `ADMIN_ID` does not already exist. Existing accounts are not modified; if the ID belongs to a non-admin, provisioning reports a configuration error. If both variables are unset, provisioning is skipped rather than using an insecure default credential. Run `node create-admin.js` to perform the same create-if-absent operation manually after setting the variables.

## Plesk deployment

Set the application root to this `backend` directory and the startup file to `server.js`. Configure `DATABASE_URL`, `JWT_SECRET`, `ADMIN_ID`, and `ADMIN_PASSWORD` in the Plesk Node.js environment settings, then run `npm install` and `npm run db:migrate:deploy`. Passenger imports and serves the exported Express app; API initialization provisions the admin account on the first request.

## Vercel deployment

Deploy from the repository root so the root `api/[...path].js` catch-all function and existing frontend routes are included. The root `vercel.json` installs backend dependencies and runs the backend build script, which generates Prisma Client from `backend/prisma/schema.prisma`. Vercel routes `/api/*` directly to the catch-all Express function, while the configured rewrites serve the frontend pages. Configure `DATABASE_URL`, `JWT_SECRET`, `ADMIN_ID`, and `ADMIN_PASSWORD` in Vercel Project Settings → Environment Variables for each deployment environment. The API allows `https://auwcmsj.com.et` and `https://auwcmsj-flax.vercel.app`; set `CORS_ORIGINS` to a comma-separated list to allow additional frontend origins. CORS credentials are enabled for cookie-based requests.

The Express app trusts the single Vercel proxy hop so IP-based rate limiting uses the forwarded client address. Prisma adds MySQL connection, pool, and socket timeouts when they are not already present in `DATABASE_URL`, and defaults the Vercel connection pool to three connections per function instance. Keep any provider-required SSL parameters in `DATABASE_URL`; the app does not disable TLS.
