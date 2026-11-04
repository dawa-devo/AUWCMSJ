let PrismaClient;
let prisma;
const connectionCache = globalThis.__auwcmPrismaConnection ||
    (globalThis.__auwcmPrismaConnection = { promise: null });

function getPrisma() {
    if (!prisma) {
        if (!PrismaClient) {
            ({ PrismaClient } = require('@prisma/client'));
        }
        prisma = globalThis.__auwcmPrismaClient ||
            (globalThis.__auwcmPrismaClient = new PrismaClient());
    }
    return prisma;
}

function createLazyPrismaProperty(property) {
    return new Proxy(function lazyPrismaProperty() {}, {
        get(target, method) {
            if (method === 'name' || method === 'length' || method === 'prototype') {
                return Reflect.get(target, method);
            }
            return (...args) => getPrisma()[property][method](...args);
        },
        apply(target, thisArg, args) {
            return getPrisma()[property](...args);
        }
    });
}

const lazyPrisma = new Proxy({}, {
    get(target, property) {
        return createLazyPrismaProperty(property);
    }
});

async function connectDatabase(req, res, next) {
    if (!process.env.DATABASE_URL) {
        console.error('MySQL connection error: DATABASE_URL is not configured.');
        return res.status(503).json({ message: 'Database connection unavailable. Please try again.' });
    }

    try {
        const client = getPrisma();
        if (!connectionCache.promise) {
            connectionCache.promise = client.$connect();
        }
        await connectionCache.promise;
    } catch (err) {
        connectionCache.promise = null;
        console.error('MySQL connection error:', err);
        return res.status(503).json({ message: 'Database connection unavailable. Please try again.' });
    }

    return next();
}

connectDatabase.prisma = lazyPrisma;

module.exports = connectDatabase;
