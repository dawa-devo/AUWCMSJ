const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const { createAuth } = require('./middleware/auth');
const {
    createRawToken,
    hashToken,
    isValidEmail,
    isStrongPassword,
    sanitizeUser,
    escapeRegex,
    sanitizeRequest
} = require('./utils/security');

let ExcelJS;
try {
    ExcelJS = require('exceljs');
} catch (err) {
    ExcelJS = null;
    console.warn('Excel export is unavailable until backend dependencies are installed.');
}

const app = express();
const PORT = Number(process.env.PORT) || 5000;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '2h';
const EMAIL_VERIFY_TTL_MS = 24 * 60 * 60 * 1000;
const REGISTRATION_TTL_MS = 2 * 60 * 60 * 1000;
const ALLOWED_ROLES = ['student', 'admin', 'teacher'];
const ALLOWED_STATUS = ['pending', 'active', 'blocked'];

app.disable('x-powered-by');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(express.json({ limit: '2mb' }));
app.use(sanitizeRequest);

const allowedOrigins = String(process.env.CORS_ORIGINS || '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

app.use(cors({
    origin(origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.length === 0) return callback(null, true);
        if (allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error('Not allowed by CORS'));
    }
}));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Too many login attempts. Please try again later.' }
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Too many registration attempts. Please try again later.' }
});

mongoose.connect(process.env.MONGO_URI, { dbName: process.env.MONGO_DB_NAME || 'auwcmsj' })
    .then(() => {
        console.log("MongoDB Connected");
    })
    .catch((err) => {
        console.error("MongoDB connection error:", err);
    });

const userSchema = new mongoose.Schema({
    studentId: { type: String, required: true, unique: true, trim: true },
    name: { type: String, required: true, trim: true },
    email: { type: String, trim: true, lowercase: true },
    gender: { type: String, enum: ['Male', 'Female', ''], default: '' },
    department: { type: String, default: '' },
    yearOfEntry: { type: String, default: '' },
    phone: { type: String, default: '' },
    profilePic: { type: String, default: '' },
    profile: {
        fullName: { type: String, default: '' },
        email: { type: String, default: '' },
        phone: { type: String, default: '' },
        profileImage: { type: String, default: '' }
    },
    preferences: {
        emailNotifications: { type: Boolean, default: true },
        registrationNotifications: { type: Boolean, default: true },
        approvalNotifications: { type: Boolean, default: true },
        systemNotifications: { type: Boolean, default: true },
        darkMode: { type: Boolean, default: false },
        compactSidebar: { type: Boolean, default: false }
    },
    password: { type: String, required: true },
    role: { type: String, enum: ALLOWED_ROLES, default: 'student' },
    status: { type: String, enum: ALLOWED_STATUS, default: 'pending' },
    emailVerified: { type: Boolean, default: false },
    emailVerifyTokenHash: { type: String, default: '' },
    emailVerifyExpires: { type: Date },
    emailVerifyUsedAt: { type: Date },
    registrationTokenHash: { type: String, default: '' },
    registrationTokenExpires: { type: Date },
    tokenVersion: { type: Number, default: 0 },
    eName: { type: String },
    ePhone: { type: String },
    eRel: { type: String },
    fName: { type: String },
    fPhone: { type: String },
    fRel: { type: String },
    academicSkill: { type: String },
    spiritualSkill: { type: String },
    contribution: { type: String },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const { authenticate, requireAdmin, requireActive, getJwtSecret } = createAuth(User);

function buildAdminSettingsPayload(user) {
    const plain = user && typeof user.toObject === 'function' ? user.toObject() : { ...(user || {}) };
    const profile = plain.profile || {};
    const preferences = plain.preferences || {};

    return {
        userId: String(plain._id || ''),
        name: String(plain.name || profile.fullName || '').trim(),
        fullName: String(profile.fullName || plain.name || '').trim(),
        email: String(plain.email || profile.email || '').trim(),
        phone: String(profile.phone || plain.phone || '').trim(),
        profileImage: String(profile.profileImage || plain.profilePic || '').trim(),
        role: plain.role || 'admin',
        status: plain.status || 'active',
        preferences: {
            emailNotifications: Boolean(preferences.emailNotifications ?? true),
            registrationNotifications: Boolean(preferences.registrationNotifications ?? true),
            approvalNotifications: Boolean(preferences.approvalNotifications ?? true),
            systemNotifications: Boolean(preferences.systemNotifications ?? true),
            darkMode: Boolean(preferences.darkMode ?? false),
            compactSidebar: Boolean(preferences.compactSidebar ?? false)
        },
        system: {
            applicationName: 'AUWCMSJ',
            userRole: 'Admin',
            backendStatus: 'online',
            databaseStatus: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
            applicationVersion: String(process.env.APP_VERSION || '1.0.0').trim() || '1.0.0'
        }
    };
}

function buildUserSettingsPayload(user) {
    const plain = user && typeof user.toObject === 'function' ? user.toObject() : { ...(user || {}) };
    const profile = plain.profile || {};
    const preferences = plain.preferences || {};

    return {
        userId: String(plain._id || ''),
        fullName: String(profile.fullName || plain.name || '').trim(),
        name: String(plain.name || profile.fullName || '').trim(),
        email: String(profile.email || plain.email || '').trim(),
        phone: String(profile.phone || plain.phone || '').trim(),
        studentId: String(plain.studentId || '').trim(),
        department: String(plain.department || '').trim(),
        yearOfEntry: String(plain.yearOfEntry || '').trim(),
        profileImage: String(profile.profileImage || plain.profilePic || '').trim(),
        role: plain.role || 'student',
        status: plain.status || 'active',
        emailVerified: Boolean(plain.emailVerified),
        registrationDate: plain.createdAt ? new Date(plain.createdAt).toISOString() : null,
        preferences: {
            emailNotifications: Boolean(preferences.emailNotifications ?? true),
            eventNotifications: Boolean(preferences.eventNotifications ?? true),
            resourceNotifications: Boolean(preferences.resourceNotifications ?? true),
            accountNotifications: Boolean(preferences.accountNotifications ?? true),
            systemNotifications: Boolean(preferences.systemNotifications ?? true),
            darkMode: Boolean(preferences.darkMode ?? false),
            compactSidebar: Boolean(preferences.compactSidebar ?? false),
            language: String(preferences.language || 'en').trim() || 'en'
        }
    };
}

let spamProtectionEnabled = false;

const messageSchema = new mongoose.Schema({
    studentId: { type: String, required: true, index: true },
    studentName: { type: String, default: '' },
    content: { type: String, required: true },
    reply: { type: String, default: '' },
    isReadByUser: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    repliedAt: { type: Date }
});
const Message = mongoose.model('Message', messageSchema);

const ContactEmergency = mongoose.model('ContactEmergency', new mongoose.Schema({
    universityId: { type: String, required: true },
    eName: String,
    ePhone: String,
    eRel: String,
    fName: String,
    fPhone: String,
    fRel: String
}));

const resourceSchema = new mongoose.Schema({
    title: String,
    category: String,
    fileName: String,
    fileUrl: String
});
const Resource = mongoose.model('Resource', resourceSchema);

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

function appBaseUrl() {
    return String(process.env.PUBLIC_APP_URL || 'http://127.0.0.1:5500').replace(/\/$/, '');
}

function verificationLink(token) {
    return `${appBaseUrl()}/frontend/verification.html?token=${encodeURIComponent(token)}`;
}

async function sendMail({ to, subject, text }) {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        throw new Error('Email credentials are missing in .env');
    }
    return transporter.sendMail({
        from: process.env.EMAIL_USER,
        to,
        subject,
        text
    });
}

const sendPasswordEmail = async (userEmail, generatedPassword, verifyToken) => {
    const verifyLine = verifyToken
        ? `\n\nVerify your email (link expires in 24 hours):\n${verificationLink(verifyToken)}`
        : '';
    return sendMail({
        to: userEmail,
        subject: 'AUWCMSJ Password',
        text: `Baga nagaan dhufte! Password kee: ${generatedPassword}${verifyLine}`
    });
};

async function sendApprovalEmail(userEmail) {
    return sendMail({
        to: userEmail,
        subject: 'AUWCMSJ Account Activated',
        text: 'Your AUWCMSJ account has been approved by an administrator. You can now log in with your student ID and password.'
    });
}

function signUserToken(user) {
    return jwt.sign(
        {
            userId: user._id,
            studentId: user.studentId,
            tokenVersion: Number(user.tokenVersion || 0)
        },
        getJwtSecret(),
        { expiresIn: JWT_EXPIRES_IN }
    );
}

async function issueEmailVerification(user) {
    const rawToken = createRawToken(32);
    user.emailVerifyTokenHash = hashToken(rawToken);
    user.emailVerifyExpires = new Date(Date.now() + EMAIL_VERIFY_TTL_MS);
    user.emailVerifyUsedAt = undefined;
    await user.save();
    return rawToken;
}

async function assertRegistrationToken(universityId, registrationToken) {
    const studentId = String(universityId || '').trim();
    const token = String(registrationToken || '').trim();
    if (!studentId || !token) {
        const error = new Error('Registration session is missing or expired. Please start from Step 1.');
        error.status = 401;
        throw error;
    }

    const user = await User.findOne({ studentId });
    if (!user) {
        const error = new Error('Barataan ID kanaan galmaa\'e User collection keessa hin jiru.');
        error.status = 404;
        throw error;
    }
    if (user.status !== 'pending') {
        const error = new Error('This registration is no longer pending.');
        error.status = 403;
        throw error;
    }
    if (!user.registrationTokenHash || !user.registrationTokenExpires) {
        const error = new Error('Registration session is missing or expired. Please start from Step 1.');
        error.status = 401;
        throw error;
    }
    if (user.registrationTokenExpires.getTime() < Date.now()) {
        const error = new Error('Registration session expired. Please start from Step 1.');
        error.status = 401;
        throw error;
    }
    if (user.registrationTokenHash !== hashToken(token)) {
        const error = new Error('Invalid registration session.');
        error.status = 401;
        throw error;
    }
    return user;
}

async function countAdmins() {
    return User.countDocuments({ role: 'admin' });
}

app.post('/api/admin/resources', authenticate, requireAdmin, async (req, res) => {
    try {
        const title = String(req.body.title || '').trim();
        if (!title) {
            return res.status(400).json({ message: 'Resource title is required.' });
        }
        const newRes = new Resource({
            title,
            category: String(req.body.category || '').trim(),
            fileName: String(req.body.fileName || '').trim(),
            fileUrl: String(req.body.fileUrl || '').trim()
        });
        await newRes.save();
        res.json({ message: 'Uploaded' });
    } catch (err) {
        res.status(500).json({ message: 'Upload failed' });
    }
});

app.get('/api/resources', authenticate, requireActive, async (req, res) => {
    try {
        const data = await Resource.find().select('-__v');
        res.json(data);
    } catch (err) {
        res.status(500).json({ message: 'Resources could not be loaded.' });
    }
});

app.post('/api/register-step1', registerLimiter, async (req, res) => {
    try {
        const universityId = String(req.body.universityId || '').trim();
        const email = String(req.body.email || '').trim().toLowerCase();
        const fullName = String(req.body.fullName || '').trim();
        const gender = String(req.body.gender || '').trim();
        const department = String(req.body.department || '').trim();
        const yearOfEntry = String(req.body.year || req.body.yearOfEntry || '').trim();
        const phone = String(req.body.phone || '').trim();

        if (!universityId || !fullName || !email || !phone) {
            return res.status(400).json({ message: 'Full name, email, university ID, and phone are required.' });
        }
        if (universityId.length > 80 || fullName.length > 160 || email.length > 254 || phone.length > 40) {
            return res.status(400).json({ message: 'One or more registration fields are too long.' });
        }
        if (!isValidEmail(email)) {
            return res.status(400).json({ message: 'Please enter a valid email address.' });
        }

        const existing = await User.findOne({ studentId: universityId });
        if (existing) return res.status(400).json({ message: 'ID is already registered!' });

        const emailTaken = await User.findOne({ email });
        if (emailTaken) return res.status(400).json({ message: 'Email is already registered.' });

        const registrationToken = createRawToken(24);
        const placeholderPassword = await bcrypt.hash(createRawToken(16), 10);

        const newUser = new User({
            studentId: universityId,
            name: fullName,
            email,
            gender: gender === 'Male' || gender === 'Female' ? gender : '',
            department,
            yearOfEntry,
            phone,
            password: placeholderPassword,
            status: 'pending',
            role: 'student',
            emailVerified: false,
            registrationTokenHash: hashToken(registrationToken),
            registrationTokenExpires: new Date(Date.now() + REGISTRATION_TTL_MS)
        });
        await newUser.save();
        res.status(200).json({ message: 'Step 1 saved!', registrationToken });
    } catch (err) {
        if (err.code === 11000) {
            return res.status(400).json({ message: 'ID or email is already registered.' });
        }
        res.status(500).json({ message: 'Registration could not be saved.' });
    }
});

app.post('/api/register-step2', registerLimiter, async (req, res) => {
    try {
        const data = req.body || {};
        if (!data.universityId) {
            return res.status(400).json({ error: 'ID barataa hin argamne. Step 1 irraa deebi\'ii yaali.' });
        }

        const updatedUser = await assertRegistrationToken(data.universityId, data.registrationToken);

        const registrationFields = ['eName', 'ePhone', 'eRel', 'fName', 'fPhone', 'fRel'];
        if (registrationFields.some((field) => String(data[field] || '').length > 160)) {
            return res.status(400).json({ error: 'Emergency contact fields are too long.' });
        }

        await ContactEmergency.findOneAndUpdate(
            { universityId: String(data.universityId).trim() },
            {
                universityId: String(data.universityId).trim(),
                eName: data.eName || '',
                ePhone: data.ePhone || '',
                eRel: data.eRel || '',
                fName: data.fName || '',
                fPhone: data.fPhone || '',
                fRel: data.fRel || ''
            },
            { upsert: true, new: true }
        );

        const generatedPassword = cryptoRandomPassword();
        const hashedPw = await bcrypt.hash(generatedPassword, 12);
        const verifyToken = createRawToken(32);

        updatedUser.password = hashedPw;
        updatedUser.eName = data.eName || '';
        updatedUser.ePhone = data.ePhone || '';
        updatedUser.eRel = data.eRel || '';
        updatedUser.fName = data.fName || '';
        updatedUser.fPhone = data.fPhone || '';
        updatedUser.fRel = data.fRel || '';
        updatedUser.emailVerifyTokenHash = hashToken(verifyToken);
        updatedUser.emailVerifyExpires = new Date(Date.now() + EMAIL_VERIFY_TTL_MS);
        updatedUser.emailVerifyUsedAt = undefined;
        updatedUser.emailVerified = false;
        await updatedUser.save();

        let emailSent = false;
        let emailError = '';
        if (updatedUser.email) {
            try {
                await sendPasswordEmail(updatedUser.email, generatedPassword, verifyToken);
                emailSent = true;
            } catch (emailErr) {
                console.error('EMAIL ERROR:', emailErr);
                emailError = emailErr.message || 'Password email could not be sent.';
            }
        } else {
            emailError = 'No email address was saved for this user.';
        }

        const allowFallback = String(process.env.ALLOW_PASSWORD_FALLBACK || 'true').toLowerCase() !== 'false'
            && process.env.NODE_ENV !== 'production';

        res.status(200).json({
            message: 'Step 2 Milkaa\'eera!',
            emailSent,
            emailError,
            generatedPassword: (!emailSent && allowFallback) ? generatedPassword : undefined
        });
    } catch (err) {
        console.error('DATABASE ERROR:', err);
        res.status(err.status || 500).json({ error: err.message });
    }
});

function cryptoRandomPassword() {
    return createRawToken(6);
}

app.post('/api/skills', async (req, res) => {
    try {
        const { universityId, academicSkill, spiritualSkill, contribution, registrationToken } = req.body || {};
        if (!universityId) {
            return res.status(400).json({ message: 'University ID is required.' });
        }

        const user = await assertRegistrationToken(universityId, registrationToken);
        if ([academicSkill, spiritualSkill, contribution].some((value) => String(value || '').length > 4000)) {
            return res.status(400).json({ message: 'Skill details are too long.' });
        }
        user.academicSkill = academicSkill || '';
        user.spiritualSkill = spiritualSkill || '';
        user.contribution = contribution || '';
        await user.save();

        res.status(200).json({ message: 'Skills saved successfully.' });
    } catch (err) {
        res.status(err.status || 500).json({ message: err.message });
    }
});

async function verifyEmailHandler(req, res) {
    try {
        const token = String(req.body?.token || req.query.token || '').trim();
        if (!token) {
            return res.status(400).json({ message: 'Verification token is required.' });
        }

        const tokenHash = hashToken(token);
        const user = await User.findOne({ emailVerifyTokenHash: tokenHash });
        if (!user) {
            return res.status(400).json({ message: 'Invalid verification token.' });
        }
        if (user.emailVerifyUsedAt) {
            return res.status(400).json({ message: 'This verification token has already been used.' });
        }
        if (!user.emailVerifyExpires || user.emailVerifyExpires.getTime() < Date.now()) {
            return res.status(400).json({ message: 'This verification token has expired.' });
        }

        user.emailVerified = true;
        user.emailVerifyUsedAt = new Date();
        user.emailVerifyTokenHash = '';
        user.emailVerifyExpires = undefined;
        await user.save();

        res.json({ message: 'Email verified successfully.', emailVerified: true });
    } catch (err) {
        res.status(500).json({ message: 'Verification failed.' });
    }
}

app.post('/api/verify-email', verifyEmailHandler);
app.get('/api/verify-email', verifyEmailHandler);

app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const studentId = String(req.body.studentId || '').trim();
        const password = String(req.body.password || '');

        if (!studentId || !password) {
            return res.status(400).json({ message: 'Student ID and password are required.' });
        }

        const user = await User.findOne({ studentId });
        if (!user) return res.status(400).json({ message: 'ID hin argamne!' });
        if (user.status === 'blocked') return res.status(403).json({ message: 'This account is blocked.' });
        if (user.status !== 'active') return res.status(403).json({ message: 'Admin mirkaneessuu eagi!' });

        const requireEmail = String(process.env.REQUIRE_EMAIL_VERIFICATION || '').toLowerCase() === 'true';
        if (requireEmail && user.role !== 'admin' && !user.emailVerified) {
            return res.status(403).json({ message: 'Please verify your email before logging in.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Password dogoggora!' });

        const token = signUserToken(user);
        res.json({
            message: 'Success',
            name: user.name,
            role: user.role,
            studentId: user.studentId,
            profilePic: user.profilePic || '',
            emailVerified: Boolean(user.emailVerified),
            token
        });
    } catch (err) {
        res.status(500).json({ message: 'Server Error' });
    }
});

app.post('/api/logout', authenticate, async (req, res) => {
    try {
        await User.updateOne(
            { _id: req.user._id },
            { $inc: { tokenVersion: 1 } }
        );
        res.json({ message: 'Logged out successfully.' });
    } catch (err) {
        res.status(500).json({ message: 'Could not log out securely.' });
    }
});

app.get('/api/user/me', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('name studentId email profilePic role status emailVerified profile preferences department yearOfEntry phone createdAt');
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        res.json(user);
    } catch (err) {
        res.status(500).json({ message: 'User profile could not be loaded.' });
    }
});

app.get('/api/user/settings', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.json({
            message: 'User settings loaded successfully.',
            settings: buildUserSettingsPayload(user)
        });
    } catch (err) {
        res.status(500).json({ message: 'User settings could not be loaded.' });
    }
});

app.put('/api/user/settings/profile', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const fullName = String(req.body.fullName || user.profile?.fullName || user.name || '').trim();
        const email = String(req.body.email || user.profile?.email || user.email || '').trim().toLowerCase();
        const phone = String(req.body.phone || user.profile?.phone || user.phone || '').trim();
        const department = String(req.body.department || user.department || '').trim();
        const yearOfEntry = String(req.body.yearOfEntry || user.yearOfEntry || '').trim();
        const profileImage = String(req.body.profileImage || req.body.profilePic || user.profile?.profileImage || user.profilePic || '').trim();

        if (!fullName) {
            return res.status(400).json({ message: 'Full name is required.' });
        }
        if (email && !isValidEmail(email)) {
            return res.status(400).json({ message: 'Please enter a valid email address.' });
        }
        if (profileImage && !profileImage.startsWith('data:image/') && !/^https?:\/\//i.test(profileImage)) {
            return res.status(400).json({ message: 'Profile image must be a valid image URL or base64 image.' });
        }

        if (email) {
            const duplicateEmailUser = await User.findOne({ email, _id: { $ne: user._id } });
            if (duplicateEmailUser) {
                return res.status(409).json({ message: 'This email is already assigned to another user.' });
            }
        }

        if (user.role !== 'admin') {
            user.name = fullName;
            user.email = email || user.email || '';
            user.phone = phone;
            user.department = department;
            user.yearOfEntry = yearOfEntry;
            user.profilePic = profileImage || user.profilePic || '';
            user.profile = {
                ...(user.profile || {}),
                fullName,
                email: email || user.profile?.email || user.email || '',
                phone,
                profileImage: profileImage || user.profile?.profileImage || user.profilePic || ''
            };
        }

        const updatedUser = await user.save();

        res.json({
            message: 'Profile updated successfully.',
            settings: buildUserSettingsPayload(updatedUser)
        });
    } catch (err) {
        res.status(500).json({ message: 'Profile could not be updated.' });
    }
});

app.put('/api/user/settings/password', authenticate, async (req, res) => {
    try {
        const currentPassword = String(req.body.currentPassword || '');
        const newPassword = String(req.body.newPassword || '');
        const confirmPassword = String(req.body.confirmPassword || '');

        if (!currentPassword || !newPassword || !confirmPassword) {
            return res.status(400).json({ message: 'Current password, new password, and confirm password are required.' });
        }
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: 'Passwords do not match.' });
        }
        if (!isStrongPassword(newPassword)) {
            return res.status(400).json({ message: 'Password does not meet security requirements.' });
        }

        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Incorrect current password.' });
        }

        user.password = await bcrypt.hash(newPassword, 12);
        user.tokenVersion = Number(user.tokenVersion || 0) + 1;
        await user.save();

        const token = signUserToken(user);
        res.json({ message: 'Password changed successfully.', token });
    } catch (err) {
        res.status(500).json({ message: 'Password could not be changed.' });
    }
});

app.put('/api/user/settings/notifications', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const previous = user.preferences || {};
        user.preferences = {
            ...previous,
            emailNotifications: Boolean(req.body.emailNotifications ?? previous.emailNotifications ?? true),
            eventNotifications: Boolean(req.body.eventNotifications ?? previous.eventNotifications ?? true),
            resourceNotifications: Boolean(req.body.resourceNotifications ?? previous.resourceNotifications ?? true),
            accountNotifications: Boolean(req.body.accountNotifications ?? previous.accountNotifications ?? true),
            systemNotifications: Boolean(req.body.systemNotifications ?? previous.systemNotifications ?? true),
            language: String(req.body.language || previous.language || 'en').trim() || 'en'
        };
        await user.save();

        res.json({
            message: 'Notification settings updated successfully.',
            settings: buildUserSettingsPayload(user)
        });
    } catch (err) {
        res.status(500).json({ message: 'Notification settings could not be updated.' });
    }
});

app.put('/api/user/settings/appearance', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const previous = user.preferences || {};
        user.preferences = {
            ...previous,
            darkMode: Boolean(req.body.darkMode ?? previous.darkMode ?? false),
            compactSidebar: Boolean(req.body.compactSidebar ?? previous.compactSidebar ?? false)
        };
        await user.save();

        res.json({
            message: 'Appearance settings updated successfully.',
            settings: buildUserSettingsPayload(user)
        });
    } catch (err) {
        res.status(500).json({ message: 'Appearance settings could not be updated.' });
    }
});

app.put('/api/user/settings/language', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const language = String(req.body.language || '').trim().toLowerCase();
        if (!['en', 'om'].includes(language)) {
            return res.status(400).json({ message: 'Language preference is invalid.' });
        }

        const previous = user.preferences || {};
        user.preferences = {
            ...previous,
            language
        };
        await user.save();

        res.json({
            message: 'Language preference updated successfully.',
            settings: buildUserSettingsPayload(user)
        });
    } catch (err) {
        res.status(500).json({ message: 'Language preference could not be updated.' });
    }
});

app.get('/api/admin/settings', authenticate, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'Admin user not found.' });
        }
        res.json({
            message: 'Settings loaded successfully.',
            settings: buildAdminSettingsPayload(user)
        });
    } catch (err) {
        res.status(500).json({ message: 'Admin settings could not be loaded.' });
    }
});

app.put('/api/admin/settings/profile', authenticate, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'Admin user not found.' });
        }

        const fullName = String(req.body.fullName || req.body.name || user.profile?.fullName || user.name || '').trim();
        const email = String(req.body.email || user.email || '').trim().toLowerCase();
        const phone = String(req.body.phone || user.profile?.phone || user.phone || '').trim();
        const profileImage = String(req.body.profileImage || req.body.profilePic || user.profile?.profileImage || user.profilePic || '').trim();

        if (!fullName) {
            return res.status(400).json({ message: 'Admin full name is required.' });
        }
        if (email && !isValidEmail(email)) {
            return res.status(400).json({ message: 'Please enter a valid email address.' });
        }
        if (profileImage && !profileImage.startsWith('data:image/') && !/^https?:\/\//i.test(profileImage)) {
            return res.status(400).json({ message: 'Profile image must be a valid image URL or base64 image.' });
        }

        const duplicateEmailUser = email ? await User.findOne({ email, _id: { $ne: user._id } }) : null;
        if (duplicateEmailUser) {
            return res.status(409).json({ message: 'This email is already assigned to another user.' });
        }

        const nextProfile = {
            ...(user.profile || {}),
            fullName,
            email,
            phone,
            profileImage
        };

        const updateData = {
            name: fullName,
            email: email || user.email || '',
            phone,
            profilePic: profileImage,
            profile: nextProfile,
            ...(phone || !user.phone ? {} : {})
        };

        if (email) {
            updateData.email = email;
        }

        const updatedUser = await User.findByIdAndUpdate(req.user._id, updateData, { new: true });
        res.json({
            message: 'Profile updated successfully.',
            settings: buildAdminSettingsPayload(updatedUser)
        });
    } catch (err) {
        res.status(500).json({ message: 'Profile could not be updated.' });
    }
});

app.put('/api/admin/settings/password', authenticate, requireAdmin, async (req, res) => {
    try {
        const currentPassword = String(req.body.currentPassword || '');
        const newPassword = String(req.body.newPassword || '');
        const confirmPassword = String(req.body.confirmPassword || '');

        if (!currentPassword || !newPassword || !confirmPassword) {
            return res.status(400).json({ message: 'Current password, new password, and confirm password are required.' });
        }
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: 'New password and confirm password do not match.' });
        }
        if (!isStrongPassword(newPassword)) {
            return res.status(400).json({ message: 'New password must be at least 8 characters and include a letter and a number.' });
        }

        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'Admin user not found.' });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Current password is incorrect.' });
        }

        user.password = await bcrypt.hash(newPassword, 12);
        user.tokenVersion = Number(user.tokenVersion || 0) + 1;
        await user.save();

        const token = signUserToken(user);
        res.json({ message: 'Password changed successfully.', token });
    } catch (err) {
        res.status(500).json({ message: 'Password could not be changed.' });
    }
});

app.put('/api/admin/settings/notifications', authenticate, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'Admin user not found.' });
        }

        const preferences = user.preferences || {};
        const updates = {
            emailNotifications: Boolean(req.body.emailNotifications ?? preferences.emailNotifications ?? true),
            registrationNotifications: Boolean(req.body.registrationNotifications ?? preferences.registrationNotifications ?? true),
            approvalNotifications: Boolean(req.body.approvalNotifications ?? preferences.approvalNotifications ?? true),
            systemNotifications: Boolean(req.body.systemNotifications ?? preferences.systemNotifications ?? true)
        };

        user.preferences = {
            ...preferences,
            ...updates
        };
        await user.save();

        res.json({
            message: 'Notification settings updated.',
            settings: buildAdminSettingsPayload(user)
        });
    } catch (err) {
        res.status(500).json({ message: 'Notification settings could not be updated.' });
    }
});

app.put('/api/admin/settings/appearance', authenticate, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'Admin user not found.' });
        }

        const preferences = user.preferences || {};
        const nextPreferences = {
            ...preferences,
            darkMode: Boolean(req.body.darkMode ?? preferences.darkMode ?? false),
            compactSidebar: Boolean(req.body.compactSidebar ?? preferences.compactSidebar ?? false)
        };

        user.preferences = nextPreferences;
        await user.save();

        res.json({
            message: 'Appearance settings updated.',
            settings: buildAdminSettingsPayload(user)
        });
    } catch (err) {
        res.status(500).json({ message: 'Appearance settings could not be updated.' });
    }
});

app.put('/api/admin/settings/logout-all-sessions', authenticate, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'Admin user not found.' });
        }

        user.tokenVersion = Number(user.tokenVersion || 0) + 1;
        await user.save();

        res.json({ message: 'All sessions were logged out successfully.' });
    } catch (err) {
        res.status(500).json({ message: 'Sessions could not be logged out.' });
    }
});

app.put('/api/user/profile-photo', authenticate, requireActive, async (req, res) => {
    try {
        const profilePic = String(req.body.profilePic || '').trim();
        if (!profilePic) {
            return res.status(400).json({ message: 'Profile image is required.' });
        }
        if (profilePic.length > 800000) {
            return res.status(400).json({ message: 'Profile image is too large.' });
        }
        if (!profilePic.startsWith('data:image/')) {
            return res.status(400).json({ message: 'Profile image must be a valid image.' });
        }

        const updatedUser = await User.findByIdAndUpdate(
            req.user._id,
            { profilePic },
            { new: true }
        ).select('profilePic');

        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found.' });
        }
        res.json({ message: 'Profile photo updated.', profilePic: updatedUser.profilePic || '' });
    } catch (err) {
        res.status(500).json({ message: 'Profile photo could not be updated.' });
    }
});

app.put('/api/user/change-password', authenticate, async (req, res) => {
    try {
        const currentPassword = String(req.body.currentPassword || '');
        const newPassword = String(req.body.newPassword || '');

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ message: 'Current password and new password are required.' });
        }
        if (!isStrongPassword(newPassword)) {
            return res.status(400).json({ message: 'New password must be at least 8 characters and include a letter and a number.' });
        }

        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Current password is incorrect.' });
        }

        user.password = await bcrypt.hash(newPassword, 12);
        user.tokenVersion = Number(user.tokenVersion || 0) + 1;
        await user.save();

        const token = signUserToken(user);
        res.json({ message: 'Password changed successfully.', token });
    } catch (err) {
        res.status(500).json({ message: 'Password could not be changed.' });
    }
});

app.post('/api/user/messages', authenticate, requireActive, async (req, res) => {
    try {
        const studentId = String(req.user.studentId || '').trim();
        const studentName = String(req.user.name || '').trim();
        const content = String(req.body.content || '').trim();

        if (!studentId || !content) {
            return res.status(400).json({ message: 'Student ID and message content are required.' });
        }
        if (content.length > 4000) {
            return res.status(400).json({ message: 'Message is too long.' });
        }

        const created = await Message.create({
            studentId,
            studentName,
            content,
            isReadByUser: false
        });

        res.status(201).json({ message: 'Comment sent to admin.', messageId: created._id });
    } catch (err) {
        res.status(500).json({ message: 'Message could not be sent.' });
    }
});

app.get('/api/user/messages', authenticate, requireActive, async (req, res) => {
    try {
        const studentId = String(req.user.studentId || '').trim();
        const rows = await Message.find({ studentId }).sort({ createdAt: -1 }).lean();
        const notifications = rows.filter((item) => item.reply && !item.isReadByUser);

        res.json({
            messages: rows,
            unreadCount: notifications.length,
            notifications: notifications.map((item) => ({
                id: String(item._id),
                text: `Admin replied: ${item.reply}`,
                repliedAt: item.repliedAt || item.createdAt
            }))
        });
    } catch (err) {
        res.status(500).json({ message: 'Messages could not be loaded.' });
    }
});

app.put('/api/user/messages/mark-read', authenticate, requireActive, async (req, res) => {
    try {
        const studentId = String(req.user.studentId || '').trim();
        await Message.updateMany({ studentId, isReadByUser: false }, { isReadByUser: true });
        res.json({ message: 'Notifications marked as read.' });
    } catch (err) {
        res.status(500).json({ message: 'Could not update notifications.' });
    }
});

async function deleteOwnedUserMessage(req, res) {
    try {
        const studentId = String(req.user.studentId || '').trim();
        const messageId = String(req.params.messageId || req.body?.messageId || '').trim();

        if (!studentId || !messageId) {
            return res.status(400).json({ message: 'Message ID is required.' });
        }
        if (!mongoose.Types.ObjectId.isValid(messageId)) {
            return res.status(400).json({ message: 'Invalid message ID.' });
        }

        const deleted = await Message.findOneAndDelete({
            _id: messageId,
            studentId
        });

        if (!deleted) {
            return res.status(404).json({ message: 'Message not found or access denied.' });
        }

        res.json({ message: 'Message deleted.' });
    } catch (err) {
        console.error('deleteOwnedUserMessage:', err);
        res.status(500).json({ message: 'Message could not be deleted.' });
    }
}

app.post('/api/user/messages/delete', authenticate, requireActive, deleteOwnedUserMessage);
app.delete('/api/user/messages/:messageId', authenticate, requireActive, deleteOwnedUserMessage);

app.get('/api/admin/messages', authenticate, requireAdmin, async (req, res) => {
    try {
        const rows = await Message.find().sort({ createdAt: -1 }).lean();
        res.json({ messages: rows });
    } catch (err) {
        res.status(500).json({ message: 'Messages could not be loaded.' });
    }
});

app.put('/api/admin/messages/reply', authenticate, requireAdmin, async (req, res) => {
    try {
        const messageId = String(req.body.messageId || '').trim();
        const reply = String(req.body.reply || '').trim();
        if (!messageId || !reply) {
            return res.status(400).json({ message: 'Message ID and reply are required.' });
        }
        if (!mongoose.Types.ObjectId.isValid(messageId)) {
            return res.status(400).json({ message: 'Invalid message ID.' });
        }

        if (reply.length > 4000) {
            return res.status(400).json({ message: 'Reply is too long.' });
        }

        const updated = await Message.findByIdAndUpdate(
            messageId,
            { reply, isReadByUser: false, repliedAt: new Date() },
            { new: true }
        );

        if (!updated) {
            return res.status(404).json({ message: 'Message not found.' });
        }

        res.json({ message: 'Reply sent successfully.' });
    } catch (err) {
        res.status(500).json({ message: 'Reply could not be sent.' });
    }
});

app.get('/', (req, res) => res.send('Server is running'));

function buildAdminStudentFilters(query = {}) {
    const filters = {};
    const department = String(query.department || '').trim();
    const search = String(query.search || '').trim();
    const status = String(query.status || '').trim().toLowerCase();
    const role = String(query.role || '').trim().toLowerCase();
    const year = String(query.year || '').trim();
    const verified = String(query.verified || '').trim().toLowerCase();

    if (department) filters.department = new RegExp(`^\\s*${escapeRegex(department)}\\s*$`, 'i');
    if (status && ALLOWED_STATUS.includes(status)) filters.status = status;
    if (role && ALLOWED_ROLES.includes(role)) filters.role = role;
    if (year) filters.yearOfEntry = new RegExp(`^${escapeRegex(year)}$`, 'i');
    if (verified === 'true' || verified === 'false') filters.emailVerified = verified === 'true';
    if (search) {
        const searchRegex = new RegExp(escapeRegex(search), 'i');
        filters.$or = [
            { studentId: searchRegex },
            { name: searchRegex },
            { email: searchRegex },
            { phone: searchRegex }
        ];
    }

    return filters;
}

app.get('/api/admin/departments', authenticate, requireAdmin, async (req, res) => {
    try {
        const departments = await User.aggregate([
            { $project: { department: { $trim: { input: { $ifNull: ['$department', ''] } } } } },
            { $match: { department: { $ne: '' } } },
            {
                $group: {
                    _id: { $toLower: '$department' },
                    department: { $first: '$department' },
                    count: { $sum: 1 }
                }
            },
            { $sort: { department: 1 } },
            { $project: { _id: 0, department: 1, count: 1 } }
        ]);

        res.json(departments);
    } catch (err) {
        console.error('Department aggregation error:', err);
        res.status(500).json({ message: 'Departments could not be loaded.' });
    }
});

app.get('/api/admin/departments/:department/students', authenticate, requireAdmin, async (req, res) => {
    try {
        const department = decodeURIComponent(String(req.params.department || '')).trim();
        if (!department) {
            return res.status(400).json({ message: 'Department is required.' });
        }

        const filters = buildAdminStudentFilters({ ...req.query, department });
        const students = await User.find(filters)
            .sort({ createdAt: -1 })
            .select('-password -emailVerifyTokenHash -registrationTokenHash -tokenVersion')
            .lean();
        const contactIds = students
            .filter((student) => !student.eName && !student.ePhone && !student.fName && !student.fPhone)
            .map((student) => student.studentId)
            .filter(Boolean);
        const contacts = contactIds.length
            ? await ContactEmergency.find({ universityId: { $in: contactIds } }).lean()
            : [];
        const contactsById = new Map(contacts.map((contact) => [String(contact.universityId), contact]));
        const merged = students.map((student) => {
            const contact = contactsById.get(String(student.studentId)) || {};
            return {
                ...student,
                eName: student.eName || contact.eName || '',
                ePhone: student.ePhone || contact.ePhone || '',
                eRel: student.eRel || contact.eRel || '',
                fName: student.fName || contact.fName || '',
                fPhone: student.fPhone || contact.fPhone || '',
                fRel: student.fRel || contact.fRel || ''
            };
        });

        res.json(merged);
    } catch (err) {
        console.error('Department students load error:', err);
        res.status(500).json({ message: 'Department students could not be loaded.' });
    }
});

app.get('/api/admin/students/export', authenticate, requireAdmin, async (req, res) => {
    try {
        if (!ExcelJS) {
            return res.status(503).json({ message: 'Excel export is unavailable. Run npm install in the backend directory.' });
        }
        const students = await User.find(buildAdminStudentFilters(req.query))
            .sort({ createdAt: -1 })
            .select('studentId name email phone department yearOfEntry eName ePhone eRel fName fPhone fRel academicSkill spiritualSkill contribution role status emailVerified createdAt')
            .lean();
        const contactIds = students
            .filter((student) => !student.eName && !student.ePhone && !student.fName && !student.fPhone)
            .map((student) => student.studentId)
            .filter(Boolean);
        const contacts = contactIds.length
            ? await ContactEmergency.find({ universityId: { $in: contactIds } }).lean()
            : [];
        const contactsById = new Map(contacts.map((contact) => [String(contact.universityId), contact]));
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Students', { views: [{ state: 'frozen', ySplit: 1 }] });
        worksheet.columns = [
            { header: 'Student ID', key: 'studentId' },
            { header: 'Full Name', key: 'fullName' },
            { header: 'Email', key: 'email' },
            { header: 'Phone', key: 'phone' },
            { header: 'Department', key: 'department' },
            { header: 'Year of Entry', key: 'year' },
            { header: 'Family Contact', key: 'familyContact' },
            { header: 'Emergency Contact', key: 'emergencyContact' },
            { header: 'Academic Skills', key: 'academicSkills' },
            { header: 'Spiritual Skills', key: 'spiritualSkills' },
            { header: 'Contribution', key: 'contribution' },
            { header: 'Role', key: 'role' },
            { header: 'Status', key: 'status' },
            { header: 'Verification Status', key: 'verification' },
            { header: 'Registration Date', key: 'registrationDate' }
        ];
        students.forEach((student) => {
            const contact = contactsById.get(String(student.studentId)) || {};
            worksheet.addRow({
                studentId: student.studentId || '',
                fullName: student.name || '',
                email: student.email || '',
                phone: student.phone || '',
                department: String(student.department || '').trim(),
                year: student.yearOfEntry || '',
                familyContact: [student.fName || contact.fName, student.fPhone || contact.fPhone, student.fRel || contact.fRel].filter(Boolean).join(' '),
                emergencyContact: [student.eName || contact.eName, student.ePhone || contact.ePhone, student.eRel || contact.eRel].filter(Boolean).join(' '),
                academicSkills: student.academicSkill || '',
                spiritualSkills: student.spiritualSkill || '',
                contribution: student.contribution || '',
                role: student.role || '',
                status: student.status || '',
                verification: student.emailVerified ? 'Verified' : 'Not verified',
                registrationDate: student.createdAt || null
            });
        });
        worksheet.autoFilter = { from: 'A1', to: `O${Math.max(students.length + 1, 1)}` };
        worksheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
        worksheet.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1B5E20' } };
        worksheet.getColumn('registrationDate').numFmt = 'yyyy-mm-dd hh:mm';
        worksheet.columns.forEach((column) => {
            let width = column.header.length + 2;
            column.eachCell({ includeEmpty: true }, (cell) => {
                width = Math.min(Math.max(width, String(cell.value || '').length + 2), 45);
                cell.alignment = { vertical: 'top', wrapText: true };
            });
            column.width = width;
        });
        const department = String(req.query.department || '').trim();
        const filenamePart = department ? department.replace(/[^a-z0-9]+/gi, '_').replace(/^_|_$/g, '') : 'All';
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="AUWCMSJ_${filenamePart || 'All'}_Students_${new Date().toISOString().slice(0, 10)}.xlsx"`);
        await workbook.xlsx.write(res);
        res.end();
    } catch (err) {
        console.error('Student export error:', err);
        res.status(500).json({ message: 'Students could not be exported.' });
    }
});

app.get('/api/admin/students', authenticate, requireAdmin, async (req, res) => {
    try {
        const students = await User.find(buildAdminStudentFilters(req.query))
            .sort({ createdAt: -1 })
            .select('-password -emailVerifyTokenHash -registrationTokenHash -tokenVersion');

        const merged = await Promise.all(
            students.map(async (student) => {
                const plain = student.toObject();
                const hasEmergencyData = plain.eName || plain.ePhone || plain.fName || plain.fPhone;
                if (hasEmergencyData) return plain;

                const contact = await ContactEmergency.findOne({ universityId: plain.studentId }).lean();
                if (!contact) return plain;

                return {
                    ...plain,
                    eName: contact.eName || plain.eName,
                    ePhone: contact.ePhone || plain.ePhone,
                    eRel: contact.eRel || plain.eRel,
                    fName: contact.fName || plain.fName,
                    fPhone: contact.fPhone || plain.fPhone,
                    fRel: contact.fRel || plain.fRel
                };
            })
        );

        res.json(merged);
    } catch (err) {
        res.status(500).json({ message: "Ragaa fiduun hin danda'amne" });
    }
});

app.delete('/api/admin/delete/:id', authenticate, requireAdmin, async (req, res) => {
    try {
        const rawId = decodeURIComponent(String(req.params.id || '')).trim();
        if (!rawId) {
            return res.status(400).json({ message: 'Student ID is required.' });
        }
        const idRegex = new RegExp(`^${escapeRegex(rawId)}$`, 'i');

        const target = await User.findOne({
            $or: [
                { studentId: rawId },
                { studentId: idRegex }
            ]
        });

        if (!target) {
            return res.status(404).json({ message: 'Barataan hin argamne' });
        }
        if (String(target._id) === String(req.user._id)) {
            return res.status(400).json({ message: 'You cannot delete your own account from this screen.' });
        }
        if (target.role === 'admin' && (await countAdmins()) <= 1) {
            return res.status(400).json({ message: 'Cannot delete the last admin account.' });
        }

        await User.deleteOne({ _id: target._id });
        res.json({ message: 'Barataa ID ' + target.studentId + ' qabu haqameera!' });
    } catch (err) {
        res.status(500).json({ message: 'Haqqii irratti rakkoon uumame' });
    }
});

async function approveStudentHandler(req, res) {
    try {
        const studentId = String(req.query.studentId || req.body?.studentId || '').trim();
        if (!studentId) {
            return res.status(400).json({ message: 'Student ID is required.' });
        }

        const idRegex = new RegExp(`^${escapeRegex(studentId)}$`, 'i');
        const updatedUser = await User.findOneAndUpdate(
            {
                $or: [
                    { studentId },
                    { studentId: idRegex }
                ]
            },
            { status: 'active', $inc: { tokenVersion: 1 } },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ message: 'Barataan hin argamne' });
        }

        if (updatedUser.email) {
            try {
                await sendApprovalEmail(updatedUser.email);
            } catch (err) {
                console.error('EMAIL ERROR:', err);
            }
        }

        res.json({ message: "Barataan mirkanaa'eera!", user: sanitizeUser(updatedUser) });
    } catch (err) {
        res.status(500).json({ message: 'Error: ' + err.message });
    }
}

app.put('/api/admin/approve', authenticate, requireAdmin, approveStudentHandler);
app.post('/api/admin/approve', authenticate, requireAdmin, approveStudentHandler);

app.post('/api/admin/block', authenticate, requireAdmin, async (req, res) => {
    try {
        const studentId = String(req.body.studentId || '').trim();
        if (!studentId) {
            return res.status(400).json({ message: 'Student ID is required.' });
        }

        const target = await User.findOne({ studentId });
        if (!target) {
            return res.status(404).json({ message: 'Barataan hin argamne' });
        }
        if (String(target._id) === String(req.user._id)) {
            return res.status(400).json({ message: 'You cannot block your own account.' });
        }

        target.status = 'blocked';
        target.tokenVersion = Number(target.tokenVersion || 0) + 1;
        await target.save();
        const updatedUser = target;

        res.json({ message: 'Member blocked successfully!', user: sanitizeUser(updatedUser) });
    } catch (err) {
        res.status(500).json({ message: 'Error: ' + err.message });
    }
});

app.post('/api/admin/add-student', authenticate, requireAdmin, async (req, res) => {
    try {
        const studentId = String(req.body.studentId || '').trim();
        const name = String(req.body.name || '').trim();
        const password = String(req.body.password || '');
        const status = ALLOWED_STATUS.includes(req.body.status) ? req.body.status : 'active';
        const role = ALLOWED_ROLES.includes(req.body.role) ? req.body.role : 'student';

        if (!studentId || !name || !password) {
            return res.status(400).json({ error: 'Student ID, name, and password are required.' });
        }
        if (!isStrongPassword(password)) {
            return res.status(400).json({ error: 'Password must be at least 8 characters and include a letter and a number.' });
        }

        const existingUser = await User.findOne({ studentId });
        if (existingUser) {
            return res.status(400).json({ error: 'Student ID already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({
            studentId,
            name,
            password: hashedPassword,
            status,
            role,
            emailVerified: true
        });

        await newUser.save();
        res.status(200).json({ message: "Barataan galmaa'eera" });
    } catch (err) {
        res.status(500).json({ error: 'Student could not be added.' });
    }
});

let latestNews = "Beeksisni ammaan tana hin jiru.";

app.post('/api/admin/news', authenticate, requireAdmin, (req, res) => {
    latestNews = String(req.body.news || '');
    res.json({ message: 'News updated' });
});

app.get('/api/news', authenticate, requireActive, (req, res) => {
    res.json({ news: latestNews });
});

app.get('/api/statistics', authenticate, requireActive, async (req, res) => {
    try {
        const students = await User.find({ role: 'student' }).select('gender status').lean();
        const total = students.length;
        const active = students.filter((student) => student.status === 'active').length;
        const male = students.filter((student) => student.gender === 'Male').length;
        const female = students.filter((student) => student.gender === 'Female').length;

        res.json({ total, active, male, female });
    } catch (err) {
        res.status(500).json({ message: "Statistics hin fe'amne" });
    }
});

const progressFile = path.join(__dirname, 'progress.json');

function readProgressRows() {
    if (!fs.existsSync(progressFile)) return [];
    const data = fs.readFileSync(progressFile, 'utf8');
    const parsed = JSON.parse(data);
    return Array.isArray(parsed) ? parsed : [];
}

app.post('/api/progress', authenticate, requireActive, (req, res) => {
    try {
        const level = String(req.body.level || '').trim();
        const detail = String(req.body.detail || '').trim();
        const student = String(req.user.name || req.user.studentId || '').trim();

        if (!student || !level || !detail) {
            return res.status(400).json({ message: 'Student, level, and detail are required.' });
        }

        const progress = {
            student,
            studentId: req.user.studentId,
            level,
            detail,
            createdAt: new Date().toISOString()
        };

        const all = readProgressRows();
        all.push(progress);
        fs.writeFileSync(progressFile, JSON.stringify(all, null, 2));
        res.json({ message: 'Saved' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Progress hin save goone' });
    }
});

app.get('/api/progress', authenticate, requireAdmin, (req, res) => {
    try {
        res.json(readProgressRows());
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Progress hin fe'amne" });
    }
});

app.delete('/api/progress/:index', authenticate, requireAdmin, (req, res) => {
    try {
        const index = Number(req.params.index);
        if (!Number.isInteger(index) || index < 0) {
            return res.status(400).json({ message: 'Valid progress index is required.' });
        }

        const rows = readProgressRows();
        if (index >= rows.length) {
            return res.status(404).json({ message: 'Progress entry not found.' });
        }

        rows.splice(index, 1);
        fs.writeFileSync(progressFile, JSON.stringify(rows, null, 2));
        res.json({ message: 'Progress deleted successfully.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Progress delete hin danda'amne" });
    }
});

async function deleteProfilePhotoHandler(req, res) {
    try {
        await User.updateOne({ _id: req.user._id }, { $unset: { profilePic: 1 } });
        res.json({ message: 'Profile photo deleted successfully.' });
    } catch (err) {
        console.error('Profile photo deletion error:', err);
        res.status(500).json({ message: 'Error deleting profile photo: ' + err.message });
    }
}

app.post('/api/user/delete-profile-photo', authenticate, requireActive, deleteProfilePhotoHandler);
app.delete('/api/user/delete-profile-photo', authenticate, requireActive, deleteProfilePhotoHandler);

app.put('/api/admin/change-role', authenticate, requireAdmin, async (req, res) => {
    try {
        const studentId = String(req.body.studentId || '').trim();
        const newRole = String(req.body.newRole || '').trim();

        if (!studentId || !newRole) {
            return res.status(400).json({ message: 'Student ID and new role are required.' });
        }
        if (!ALLOWED_ROLES.includes(newRole)) {
            return res.status(400).json({ message: 'Invalid role. Must be student, admin, or teacher.' });
        }

        const user = await User.findOne({ studentId });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        if (String(user._id) === String(req.user._id) && newRole !== 'admin') {
            return res.status(400).json({ message: 'You cannot remove your own admin role.' });
        }
        if (user.role === 'admin' && newRole !== 'admin' && (await countAdmins()) <= 1) {
            return res.status(400).json({ message: 'Cannot demote the last admin.' });
        }

        user.role = newRole;
        user.tokenVersion = Number(user.tokenVersion || 0) + 1;
        await user.save();

        res.json({ message: `Role changed to ${newRole} successfully.` });
    } catch (err) {
        console.error('Role change error:', err);
        res.status(500).json({ message: 'Error changing role: ' + err.message });
    }
});

app.put('/api/admin/update-user', authenticate, requireAdmin, async (req, res) => {
    try {
        const studentId = String(req.body.studentId || '').trim();
        const name = req.body.name;
        const email = req.body.email;
        const status = req.body.status;
        const role = req.body.role;

        if (!studentId) {
            return res.status(400).json({ message: 'Student ID is required.' });
        }

        const user = await User.findOne({ studentId });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const updateData = {};
        if (name) updateData.name = String(name).trim();
        if (email) {
            const nextEmail = String(email).trim().toLowerCase();
            if (!isValidEmail(nextEmail)) {
                return res.status(400).json({ message: 'Please enter a valid email address.' });
            }
            updateData.email = nextEmail;
        }
        if (status) {
            if (!ALLOWED_STATUS.includes(status)) {
                return res.status(400).json({ message: 'Invalid status.' });
            }
            updateData.status = status;
        }
        if (role) {
            if (!ALLOWED_ROLES.includes(role)) {
                return res.status(400).json({ message: 'Invalid role.' });
            }
            if (String(user._id) === String(req.user._id) && role !== 'admin') {
                return res.status(400).json({ message: 'You cannot remove your own admin role.' });
            }
            if (user.role === 'admin' && role !== 'admin' && (await countAdmins()) <= 1) {
                return res.status(400).json({ message: 'Cannot demote the last admin.' });
            }
            updateData.role = role;
        }

        if (updateData.role || updateData.status === 'blocked') {
            updateData.tokenVersion = Number(user.tokenVersion || 0) + 1;
        }

        await User.updateOne({ studentId }, updateData);
        res.json({ message: 'User information updated successfully.' });
    } catch (err) {
        console.error('Update user error:', err);
        res.status(500).json({ message: 'Error updating user information: ' + err.message });
    }
});

app.put('/api/admin/reset-password', authenticate, requireAdmin, async (req, res) => {
    try {
        const studentId = String(req.body.studentId || '').trim();
        const newPassword = String(req.body.newPassword || '');

        if (!studentId || !newPassword) {
            return res.status(400).json({ message: 'Student ID and new password are required.' });
        }
        if (!isStrongPassword(newPassword)) {
            return res.status(400).json({ message: 'New password must be at least 8 characters and include a letter and a number.' });
        }

        const user = await User.findOne({ studentId });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 12);
        user.password = hashedPassword;
        user.tokenVersion = Number(user.tokenVersion || 0) + 1;
        await user.save();
        res.json({ message: 'Password reset successfully.' });
    } catch (err) {
        console.error('Admin reset password error:', err);
        res.status(500).json({ message: 'Error resetting password: ' + err.message });
    }
});

app.get('/api/admin/spam-protection', authenticate, requireAdmin, (req, res) => {
    res.json({ enabled: spamProtectionEnabled });
});

app.put('/api/admin/spam-protection', authenticate, requireAdmin, (req, res) => {
    spamProtectionEnabled = Boolean(req.body?.enabled);
    res.json({
        message: `Spam protection ${spamProtectionEnabled ? 'enabled' : 'disabled'}.`,
        enabled: spamProtectionEnabled
    });
});

app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    console.error(err);
    res.status(500).json({ message: 'Unexpected server error.' });
});

app.listen(PORT, '0.0.0.0', () => console.log(`Server on port ${PORT}`));
