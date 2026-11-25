const bcrypt = require('bcryptjs');
const { isStrongPassword } = require('./security');

async function ensureAdminAccount(prisma, env = process.env) {
    const adminId = String(env.ADMIN_ID || '').trim();
    const adminPassword = String(env.ADMIN_PASSWORD || '');

    if (!adminId && !adminPassword) {
        console.warn('Admin account provisioning skipped. Set ADMIN_ID and ADMIN_PASSWORD to enable it.');
        return { created: false, skipped: true };
    }

    if (!adminId || !adminPassword) {
        throw new Error('Both ADMIN_ID and ADMIN_PASSWORD must be configured.');
    }
    if (adminId.length > 80) {
        throw new Error('ADMIN_ID must be 80 characters or fewer.');
    }
    if (Buffer.byteLength(adminPassword, 'utf8') > 72) {
        throw new Error('ADMIN_PASSWORD must be 72 bytes or fewer for bcrypt.');
    }
    if (!isStrongPassword(adminPassword)) {
        throw new Error('ADMIN_PASSWORD must be at least 8 characters and contain letters and numbers.');
    }

    const existing = await prisma.user.findUnique({ where: { studentId: adminId } });
    if (existing) {
        if (String(existing.role || '').toLowerCase() !== 'admin') {
            throw new Error('ADMIN_ID is already assigned to a non-admin account.');
        }
        console.info('Configured admin account already exists; leaving its credentials and status unchanged.');
        return { created: false, skipped: false };
    }

    const passwordHash = await bcrypt.hash(adminPassword, 12);
    try {
        await prisma.user.create({
            data: {
                studentId: adminId,
                name: 'System Administrator',
                password: passwordHash,
                role: 'admin',
                status: 'active'
            }
        });
        console.info('Configured admin account created.');
        return { created: true, skipped: false };
    } catch (error) {
        if (error.code !== 'P2002') throw error;

        const concurrentAccount = await prisma.user.findUnique({ where: { studentId: adminId } });
        if (String(concurrentAccount?.role || '').toLowerCase() !== 'admin') {
            throw new Error('ADMIN_ID is already assigned to a non-admin account.');
        }
        console.info('Configured admin account already exists; leaving its credentials and status unchanged.');
        return { created: false, skipped: false };
    }
}

module.exports = { ensureAdminAccount };
