require("dotenv").config();
const { PrismaClient } = require("@prisma/client");
const { ensureAdminAccount } = require("./utils/admin-account");
const prisma = new PrismaClient();

async function createAdmin() {
    try {
        if (!process.env.DATABASE_URL) {
            throw new Error("DATABASE_URL is not configured.");
        }
        await prisma.$connect();
        console.log("MySQL connected");

        const result = await ensureAdminAccount(prisma);
        if (result.skipped) {
            throw new Error("Set ADMIN_ID and ADMIN_PASSWORD before creating the admin account.");
        }

    } catch (error) {
        console.error("Error creating admin:", error);
        process.exitCode = 1;
    } finally {
        await prisma.$disconnect();
    }
}

createAdmin();