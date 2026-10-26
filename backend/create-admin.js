const bcrypt = require("bcryptjs");
require("dotenv").config();
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

async function createAdmin() {
    try {
        if (!process.env.DATABASE_URL) {
            throw new Error("DATABASE_URL is not configured.");
        }
        await prisma.$connect();
        console.log("MySQL connected");

        const adminId = "admin001";
        const adminPassword = "Admin@12345";

        const hashedPassword = await bcrypt.hash(adminPassword, 12);

        await prisma.user.upsert({
            where: { studentId: adminId },
            update: {
                name: "System Administrator",
                password: hashedPassword,
                role: "admin",
                status: "active"
            },
            create: {
                studentId: adminId,
                name: "System Administrator",
                password: hashedPassword,
                role: "admin",
                status: "active"
            }
        });
        console.log("Admin account created or updated");

        console.log("Admin ID:", adminId);

    } catch (error) {
        console.error("Error creating admin:", error);
        process.exitCode = 1;
    } finally {
        await prisma.$disconnect();
    }
}

createAdmin();