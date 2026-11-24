# Backend setup

The backend uses Prisma ORM with MySQL. From this directory:

1. Copy `.env.example` to `.env` and set `DATABASE_URL` to the MySQL connection URL, for example `mysql://USER:PASSWORD@localhost:3306/auwcmsj`.
2. Create the `auwcmsj` database in MySQL.
3. Run `npm install`. The `postinstall` script generates the Prisma client; you can also run `npm run db:generate` explicitly.
4. Run `npm run db:migrate -- --name init` to create the Prisma migration and tables.
5. Start the API with `node server.js`.

Run `node create-admin.js` to create or update the initial admin account after the database is migrated.

## Plesk deployment

Set the application root to this `backend` directory and the startup file to `server.js`. Configure `DATABASE_URL` and `JWT_SECRET` in the Plesk Node.js environment settings, then run `npm install` and `npm run db:migrate:deploy`. Passenger imports and serves the exported Express app; `server.js` only opens a standalone listener when run directly.

## Vercel deployment

Deploy from the repository root so the root `api/index.js` function and existing frontend routes are included. The root `vercel.json` installs backend dependencies and runs the backend build script, which generates Prisma Client from `backend/prisma/schema.prisma`, then rewrites unmatched requests to the Express app. Configure `DATABASE_URL` and `JWT_SECRET` in Vercel's project environment. The API allows `https://auwcmsj.com.et` and `https://auwcmsj-flax.vercel.app`; set `CORS_ORIGINS` to a comma-separated list to allow additional frontend origins. CORS credentials are enabled for cookie-based requests.

The Express app trusts the single Vercel proxy hop so IP-based rate limiting uses the forwarded client address. Prisma adds MySQL connection, pool, and socket timeouts when they are not already present in `DATABASE_URL`, and defaults the Vercel connection pool to three connections per function instance. Keep any provider-required SSL parameters in `DATABASE_URL`; the app does not disable TLS.
