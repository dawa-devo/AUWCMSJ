let PrismaClient;
let prisma;
const connectionCache = globalThis.__auwcmPrismaConnection ||
    (globalThis.__auwcmPrismaConnection = { promise: null });

function getPrisma() {
    if (!prisma) {
        if (!PrismaClient) {
            ({ PrismaClient } = require('@prisma/client'));
        }
        const databaseUrl = new URL(process.env.DATABASE_URL);
        const setDefault = (name, value) => {
            if (!databaseUrl.searchParams.has(name)) {
                databaseUrl.searchParams.set(name, value);
            }
        };
        setDefault('connect_timeout', '5');
        setDefault('pool_timeout', '5');
        setDefault('socket_timeout', '10');
        if (process.env.VERCEL) {
            setDefault('connection_limit', '3');
        }

        prisma = globalThis.__auwcmPrismaClient ||
            (globalThis.__auwcmPrismaClient = new PrismaClient({
                datasources: { db: { url: databaseUrl.toString() } }
            }));
    }
    return prisma;
}

function connectWithTimeout(client) {
    let timeoutId;
    const timeout = new Promise((resolve, reject) => {
        timeoutId = setTimeout(() => reject(new Error('Database connection timed out.')), 8000);
    });

    return Promise.race([
        Promise.resolve().then(() => client.$connect()),
        timeout
    ]).finally(() => clearTimeout(timeoutId));
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
            connectionCache.promise = connectWithTimeout(client);
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
