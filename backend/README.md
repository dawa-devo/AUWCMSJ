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
