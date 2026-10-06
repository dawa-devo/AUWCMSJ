const crypto = require('crypto');

function createRawToken(bytes = 32) {
    return crypto.randomBytes(bytes).toString('hex');
}

function hashToken(token) {
    return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function isStrongPassword(password) {
    const value = String(password || '');
    if (value.length < 8) return false;
    return /[A-Za-z]/.test(value) && /\d/.test(value);
}

function sanitizeUser(user) {
    if (!user) return null;
    const plain = typeof user.toObject === 'function' ? user.toObject() : { ...user };
    delete plain.password;
    delete plain.registrationTokenHash;
    delete plain.tokenVersion;
    delete plain.__v;
    return plain;
}

function escapeRegex(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function stripDangerousKeys(value) {
    if (Array.isArray(value)) {
        return value.map(stripDangerousKeys);
    }
    if (value && typeof value === 'object') {
        const clean = {};
        for (const [key, nested] of Object.entries(value)) {
            if (key.startsWith('$') || key.includes('.')) continue;
            clean[key] = stripDangerousKeys(nested);
        }
        return clean;
    }
    return value;
}

function sanitizeRequest(req, _res, next) {
    if (req.body && typeof req.body === 'object') {
        req.body = stripDangerousKeys(req.body);
    }
    next();
}

module.exports = {
    createRawToken,
    hashToken,
    isStrongPassword,
    sanitizeUser,
    escapeRegex,
    sanitizeRequest
};
