const mongoose = require('mongoose');

const connectionCache = globalThis.__auwcmMongooseCache ||
    (globalThis.__auwcmMongooseCache = { promise: null });

async function connectDatabase(req, res, next) {
    if (mongoose.connection.readyState === 1) {
        return next();
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
                socketTimeoutMS: 15000
            }).then(() => mongoose.connection);
        }
        connectionPromise = connectionCache.promise;
        await connectionPromise;
    } catch (err) {
        console.error('MongoDB connection error:', err);
        return res.status(503).json({ message: 'Database connection unavailable. Please try again.' });
    } finally {
        if (connectionPromise && connectionCache.promise === connectionPromise) {
            connectionCache.promise = null;
        }
    }

    return next();
}

module.exports = connectDatabase;
