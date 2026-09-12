const jwt = require('jsonwebtoken');

function getJwtSecret() {
    const secret = String(process.env.JWT_SECRET || '').trim();
    if (!secret) {
        throw new Error('JWT_SECRET is not configured.');
    }
    return secret;
}

function createAuth(User) {
    async function authenticate(req, res, next) {
        const authHeader = req.headers.authorization || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

        if (!token) {
            return res.status(401).json({ message: 'Authentication token is required.' });
        }

        try {
            const decoded = jwt.verify(token, getJwtSecret());
            const user = await User.findById(decoded.userId);
            if (!user) {
                return res.status(401).json({ message: 'Invalid or expired token.' });
            }

            const tokenVersion = Number(decoded.tokenVersion || 0);
            if (Number(user.tokenVersion || 0) !== tokenVersion) {
                return res.status(401).json({ message: 'Session is no longer valid. Please log in again.' });
            }

            if (user.status === 'blocked') {
                return res.status(403).json({ message: 'This account is blocked.' });
            }

            req.user = user;
            req.auth = {
                userId: String(user._id),
                studentId: user.studentId,
                role: user.role,
                status: user.status,
                emailVerified: Boolean(user.emailVerified)
            };
            next();
        } catch (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ message: 'Session expired. Please log in again.' });
            }
            return res.status(401).json({ message: 'Invalid or expired token.' });
        }
    }

    function requireRole(...roles) {
        const allowed = roles.map((role) => String(role).toLowerCase());
        return (req, res, next) => {
            if (!req.user) {
                return res.status(401).json({ message: 'Authentication token is required.' });
            }
            const currentRole = String(req.user.role || '').toLowerCase();
            if (!allowed.includes(currentRole)) {
                return res.status(403).json({ message: 'You do not have permission to perform this action.' });
            }
            next();
        };
    }

    function requireActive(req, res, next) {
        if (!req.user) {
            return res.status(401).json({ message: 'Authentication token is required.' });
        }
        if (req.user.status !== 'active') {
            return res.status(403).json({ message: 'Account is not activated yet. Wait for admin verification.' });
        }

        const requireEmail = String(process.env.REQUIRE_EMAIL_VERIFICATION || '').toLowerCase() === 'true';
        if (requireEmail && req.user.role !== 'admin' && !req.user.emailVerified) {
            return res.status(403).json({ message: 'Please verify your email before using this feature.' });
        }
        next();
    }

    const requireAdmin = requireRole('admin');
    const authorize = requireRole;

    return {
        authenticate,
        requireRole,
        requireAdmin,
        requireActive,
        authorize,
        getJwtSecret
    };
}

module.exports = { createAuth, getJwtSecret };
