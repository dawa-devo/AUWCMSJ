const mongoose = require('mongoose');

const connectionCache = globalThis.__auwcmMongooseCache ||
    (globalThis.__auwcmMongooseCache = { connection: null, promise: null });

async function connectDatabase(req, res, next) {
    if (mongoose.connection.readyState === 1) {
        connectionCache.connection = mongoose.connection;
        return next();
    }
    if (connectionCache.connection && mongoose.connection.readyState !== 2) {
        connectionCache.connection = null;
        connectionCache.promise = null;
    }

    if (!process.env.MONGO_URI) {
        console.error('MongoDB connection error: MONGO_URI is not configured.');
        return res.status(503).json({ message: 'Database connection unavailable. Please try again.' });
    }

    let connectionPromise;
    try {
        if (!connectionCache.promise) {
            connectionCache.promise = mongoose.connect(process.env.MONGO_URI, {
                dbName: process.env.MONGO_DB_NAME || 'auwcmsj',
                serverSelectionTimeoutMS: 10000,
                socketTimeoutMS: 15000,
                maxPoolSize: 10,
                minPoolSize: 0,
                maxConnecting: 2,
                maxIdleTimeMS: 30000,
                waitQueueTimeoutMS: 10000
            }).then((connection) => {
                connectionCache.connection = connection;
                return connection;
            });
        }
        connectionPromise = connectionCache.promise;
        await connectionPromise;
    } catch (err) {
        if (connectionCache.promise === connectionPromise) {
            connectionCache.promise = null;
            connectionCache.connection = null;
        }
        console.error('MongoDB connection error:', err);
        return res.status(503).json({ message: 'Database connection unavailable. Please try again.' });
    }

    return next();
}

module.exports = connectDatabase;
