const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const MONGO_URI =
    process.env.MONGO_URI || "mongodb://127.0.0.1:27017/auwcmsj";

const userSchema = new mongoose.Schema({
    studentId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    email: String,
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
    },
    emailVerified: { type: Boolean, default: true }
});

const User = mongoose.model("User", userSchema);

async function createAdmin() {
    try {
        await mongoose.connect(MONGO_URI);
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
            existingAdmin.emailVerified = true;

            await existingAdmin.save();
            console.log("Existing account updated to ADMIN");
        } else {
            await User.create({
                studentId: adminId,
                name: "System Administrator",
                email: "admin@auwcmsj.com",
                password: hashedPassword,
                role: "admin",
                status: "active",
                emailVerified: true
            });

            console.log("New ADMIN account created");
        }

        console.log("Admin ID:", adminId);
        console.log("Admin Password:", adminPassword);

        await mongoose.disconnect();
    } catch (error) {
        console.error("Error creating admin:", error);
        process.exit(1);
    }
}

createAdmin();