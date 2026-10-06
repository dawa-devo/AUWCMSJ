const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const MONGO_URI =
    process.env.MONGO_URI || "mongodb://127.0.0.1:27017/auwcmsj";

const userSchema = new mongoose.Schema({
    studentId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    password: { type: String, required: true },
    role: {
        type: String,
        enum: ["student", "admin", "teacher"],
        default: "student"
    },
    status: {
        type: String,
        enum: ["pending", "active", "blocked"],
        default: "pending"
    }
});

const User = mongoose.model("User", userSchema);

async function createAdmin() {
    try {
        await mongoose.connect(MONGO_URI, {
            dbName: process.env.MONGO_DB_NAME || 'auwcmsj'
        });
        console.log("MongoDB connected");

        const adminId = "admin001";
        const adminPassword = "Admin@12345";

        const hashedPassword = await bcrypt.hash(adminPassword, 12);

        const existingAdmin = await User.findOne({ studentId: adminId });

        if (existingAdmin) {
            existingAdmin.name = "System Administrator";
            existingAdmin.password = hashedPassword;
            existingAdmin.role = "admin";
            existingAdmin.status = "active";

            await existingAdmin.save();
            console.log("Existing account updated to ADMIN");
        } else {
            await User.create({
                studentId: adminId,
                name: "System Administrator",
                password: hashedPassword,
                role: "admin",
                status: "active"
            });

            console.log("New ADMIN account created");
        }

        console.log("Admin ID:", adminId);

        await mongoose.disconnect();
    } catch (error) {
        console.error("Error creating admin:", error);
        process.exit(1);
    }
}

createAdmin();