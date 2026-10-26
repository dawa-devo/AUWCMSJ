const { PrismaClient } = require('@prisma/client');

const prisma = globalThis.__auwcmPrismaClient ||
    (globalThis.__auwcmPrismaClient = new PrismaClient());
const connectionCache = globalThis.__auwcmPrismaConnection ||
    (globalThis.__auwcmPrismaConnection = { promise: null });

async function connectDatabase(req, res, next) {
    if (!process.env.DATABASE_URL) {
        console.error('MySQL connection error: DATABASE_URL is not configured.');
        return res.status(503).json({ message: 'Database connection unavailable. Please try again.' });
    }

    try {
        if (!connectionCache.promise) {
            connectionCache.promise = prisma.$connect();
        }
        await connectionCache.promise;
    } catch (err) {
        connectionCache.promise = null;
        console.error('MySQL connection error:', err);
        return res.status(503).json({ message: 'Database connection unavailable. Please try again.' });
    }

    return next();
}

connectDatabase.prisma = prisma;

module.exports = connectDatabase;
