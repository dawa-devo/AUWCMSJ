const express = require('express');
const crypto = require('crypto');
const { Readable } = require('stream');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const { createAuth } = require('./middleware/auth');
const connectDatabase = require('./middleware/database');
const prisma = connectDatabase.prisma;
const {
    createRawToken,
    hashToken,
    isStrongPassword,
    sanitizeUser,
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
const REGISTRATION_TTL_MS = 2 * 60 * 60 * 1000;
const MAX_RESOURCE_FILE_SIZE = 25 * 1024 * 1024;
const ALLOWED_ROLES = ['student', 'admin', 'teacher'];
const ALLOWED_STATUS = ['pending', 'active', 'blocked'];
const RESOURCE_FILE_TYPES = new Map([
    ['application/pdf', ['.pdf']],
    ['application/msword', ['.doc']],
    ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', ['.docx']],
    ['image/jpeg', ['.jpg', '.jpeg']],
    ['image/png', ['.png']],
    ['image/gif', ['.gif']],
    ['image/webp', ['.webp']]
]);

app.disable('x-powered-by');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(express.json({ limit: '2mb' }));
app.use(sanitizeRequest);

const configuredOrigins = String(process.env.CORS_ORIGINS || '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
const allowedOrigins = new Set([
    ...configuredOrigins,
    'https://auwcmsj-flax.vercel.app'
]);

app.use(cors({
    origin(origin, callback) {
        if (!origin) return callback(null, true);
        if (configuredOrigins.length === 0) return callback(null, true);
        if (allowedOrigins.has(origin)) return callback(null, true);
        return callback(new Error('Not allowed by CORS'));
    }
}));
app.use('/api', connectDatabase);

const resourceUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: MAX_RESOURCE_FILE_SIZE, files: 1, fields: 2 },
    fileFilter(req, file, callback) {
        const extensions = RESOURCE_FILE_TYPES.get(file.mimetype);
        const extension = path.extname(file.originalname).toLowerCase();
        if (!extensions || !extensions.includes(extension)) {
            const error = new Error('Upload a PDF, Word document, or supported image file.');
            error.status = 400;
            return callback(error);
        }
        return callback(null, true);
    }
});

function parseResourceUpload(req, res, next) {
    resourceUpload.single('file')(req, res, (err) => {
        if (!err) return next();
        const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
        return res.status(status).json({
            message: status === 413
                ? 'Resource files must be 25 MB or smaller.'
                : err.message || 'Resource upload could not be processed.'
        });
    });
}

function configureCloudinary() {
    const cloudName = String(process.env.CLOUDINARY_CLOUD_NAME || '').trim();
    const apiKey = String(process.env.CLOUDINARY_API_KEY || '').trim();
    const apiSecret = String(process.env.CLOUDINARY_API_SECRET || '').trim();
    if (!cloudName || !apiKey || !apiSecret) {
        const error = new Error('Cloudinary is not configured. Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, and CLOUDINARY_API_SECRET.');
        error.status = 503;
        throw error;
    }
    cloudinary.config({ cloud_name: cloudName, api_key: apiKey, api_secret: apiSecret });
}

function uploadResourceToCloudinary(file) {
    configureCloudinary();
    const resourceType = file.mimetype.startsWith('image/') ? 'image' : 'raw';
    const extension = path.extname(file.originalname).toLowerCase();
    const publicId = `${crypto.randomBytes(16).toString('hex')}${resourceType === 'raw' ? extension : ''}`;

    return new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
            { folder: 'digital-library', public_id: publicId, resource_type: resourceType },
            (error, result) => {
                if (error) return reject(error);
                if (!result?.secure_url || !result.public_id) {
                    return reject(new Error('Cloudinary did not return a secure file URL and public ID.'));
                }
                return resolve(result);
            }
        );
        Readable.from([file.buffer]).pipe(stream);
    });
}

async function deleteCloudinaryResource(resource) {
    if (!resource.publicId) return;
    configureCloudinary();
    const result = await cloudinary.uploader.destroy(resource.publicId, {
        resource_type: resource.resourceType || 'raw',
        invalidate: true
    });
    if (result.result !== 'ok' && result.result !== 'not found') {
        throw new Error(`Cloudinary deletion returned "${result.result || 'no result'}".`);
    }
}

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Too many login attempts. Please try again later.' }
});

const registerLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 400,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Too many registration attempts. Please try again later.' }
});

const User = prisma.user;
const { authenticate, requireAdmin, requireActive, getJwtSecret } = createAuth(prisma);

function buildAdminSettingsPayload(user) {
    const plain = user && typeof user.toObject === 'function' ? user.toObject() : { ...(user || {}) };
    const profile = plain.profile || {};
    const preferences = plain.preferences || {};

    return {
        userId: String(plain.id || ''),
        name: String(plain.name || profile.fullName || '').trim(),
        fullName: String(profile.fullName || plain.name || '').trim(),
        phone: String(profile.phone || plain.phone || '').trim(),
        profileImage: String(profile.profileImage || plain.profilePic || '').trim(),
        role: plain.role || 'admin',
        status: plain.status || 'active',
        preferences: {
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
            databaseStatus: 'connected',
            applicationVersion: String(process.env.APP_VERSION || '1.0.0').trim() || '1.0.0'
        }
    };
}

function buildUserSettingsPayload(user) {
    const plain = user && typeof user.toObject === 'function' ? user.toObject() : { ...(user || {}) };
    const profile = plain.profile || {};
    const preferences = plain.preferences || {};

    return {
        userId: String(plain.id || ''),
        fullName: String(profile.fullName || plain.name || '').trim(),
        name: String(plain.name || profile.fullName || '').trim(),
        phone: String(profile.phone || plain.phone || '').trim(),
        studentId: String(plain.studentId || '').trim(),
        department: String(plain.department || '').trim(),
        yearOfEntry: String(plain.yearOfEntry || '').trim(),
        profileImage: String(profile.profileImage || plain.profilePic || '').trim(),
        role: plain.role || 'student',
        status: plain.status || 'active',
        registrationDate: plain.createdAt ? new Date(plain.createdAt).toISOString() : null,
        preferences: {
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

const Message = prisma.message;
const ContactEmergency = prisma.contactEmergency;
const Resource = prisma.resource;

function toApiRecord(record) {
    if (!record) return record;
    const { id, ...fields } = record;
    return { _id: id, ...fields };
}

function signUserToken(user) {
    return jwt.sign(
        {
            userId: String(user.id),
            studentId: user.studentId,
            role: String(user.role || '').toLowerCase(),
            tokenVersion: Number(user.tokenVersion || 0)
        },
        getJwtSecret(),
        { expiresIn: JWT_EXPIRES_IN }
    );
}

async function assertRegistrationToken(universityId, registrationToken) {
    const studentId = String(universityId || '').trim();
    const token = String(registrationToken || '').trim();
    if (!studentId || !token) {
        const error = new Error('Registration session is missing or expired. Please start from Step 1.');
        error.status = 401;
        throw error;
    }

    const user = await User.findUnique({ where: { studentId } });
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
    return User.count({ where: { role: 'admin' } });
}

app.post('/api/admin/resources', authenticate, requireAdmin, parseResourceUpload, async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'Choose a PDF, Word document, or image file to upload.' });
    }

    const title = String(req.body.title || '').trim();
    if (!title) {
        return res.status(400).json({ message: 'Resource title is required.' });
    }

    let cloudAsset;
    try {
        cloudAsset = await uploadResourceToCloudinary(req.file);
        const newRes = await Resource.create({ data: {
            title,
            category: String(req.body.category || '').trim(),
            fileName: String(req.file.originalname).replace(/^.*[\\/]/, '').slice(0, 255),
            fileUrl: cloudAsset.secure_url,
            publicId: cloudAsset.public_id,
            resourceType: cloudAsset.resource_type,
            mimeType: req.file.mimetype
        } });
        return res.status(201).json({ message: 'Resource uploaded successfully.', resource: toApiRecord(newRes) });
    } catch (err) {
        if (cloudAsset?.public_id) {
            try {
                await deleteCloudinaryResource({
                    publicId: cloudAsset.public_id,
                    resourceType: cloudAsset.resource_type
                });
            } catch (cleanupError) {
                console.error('Cloudinary cleanup failed after resource upload error:', cleanupError);
            }
        }
        console.error('Resource upload failed:', err);
        const status = err.status === 503 ? 503 : cloudAsset ? 500 : 502;
        return res.status(status).json({
            message: status === 503
                ? err.message
                : status === 502
                    ? 'The resource could not be uploaded to cloud storage.'
                    : 'The resource was uploaded but could not be saved.'
        });
    }
});

async function findResourcesWithUploadDates() {
    const resources = await Resource.findMany({ orderBy: { createdAt: 'desc' } });
    return resources.map((resource) => ({
        _id: resource.id,
        title: resource.title,
        category: resource.category,
        fileName: resource.fileName,
        fileUrl: resource.fileUrl,
        mimeType: resource.mimeType,
        createdAt: resource.createdAt,
        uploadedAt: resource.createdAt
    }));
}

app.get('/api/admin/resources', authenticate, requireAdmin, async (req, res) => {
    try {
        return res.json(await findResourcesWithUploadDates());
    } catch (err) {
        console.error('Admin resource list loading failed:', err);
        return res.status(500).json({ message: 'Resources could not be loaded.' });
    }
});

async function deleteResourceHandler(req, res) {
    let resource;
    try {
        resource = await Resource.findUnique({ where: { id: req.params.id } });
    } catch (err) {
        console.error('Resource lookup failed before deletion:', err);
        return res.status(500).json({ message: 'Resource could not be loaded for deletion.' });
    }
    if (!resource) return res.status(404).json({ message: 'Resource not found.' });

    try {
        await deleteCloudinaryResource(resource);
    } catch (err) {
        console.error('Cloudinary resource deletion failed:', err);
        return res.status(err.status || 502).json({
            message: err.status === 503
                ? err.message
                : 'Resource storage could not be deleted; the database record was retained.'
        });
    }

    try {
        await Resource.delete({ where: { id: resource.id } });
        return res.json({ message: 'Resource deleted successfully.' });
    } catch (err) {
        console.error('Resource database deletion failed after cloud file removal:', err);
        return res.status(500).json({
            message: 'The cloud file was deleted, but its database record could not be removed.'
        });
    }
}

app.delete(
    ['/api/admin/resources/:id', '/api/resources/:id'],
    authenticate,
    requireAdmin,
    deleteResourceHandler
);

app.get('/api/resources', authenticate, requireActive, async (req, res) => {
    try {
        return res.json(await findResourcesWithUploadDates());
    } catch (err) {
        console.error('Resource list loading failed:', err);
        return res.status(500).json({ message: 'Resources could not be loaded.' });
    }
});

app.post('/api/register-step1', registerLimiter, async (req, res) => {
    try {
        const universityId = String(req.body.universityId || '').trim();
        const fullName = String(req.body.fullName || '').trim();
        const gender = String(req.body.gender || '').trim();
        const department = String(req.body.department || '').trim();
        const yearOfEntry = String(req.body.year || req.body.yearOfEntry || '').trim();
        const phone = String(req.body.phone || '').trim();

        if (!universityId || !fullName || !phone) {
            return res.status(400).json({ message: 'Error: Full name, university ID, and phone are required.' });
        }
        if (universityId.length > 80 || fullName.length > 160 || phone.length > 40) {
            return res.status(400).json({ message: 'One or more registration fields are too long.' });
        }

        const existing = await User.findUnique({ where: { studentId: universityId } });
        if (existing) return res.status(400).json({ message: 'ID is already registered!' });

        const registrationToken = createRawToken(24);
        const placeholderPassword = await bcrypt.hash(createRawToken(16), 10);

        await User.create({ data: {
            studentId: universityId,
            name: fullName,
            gender: gender === 'Male' || gender === 'Female' ? gender : '',
            department,
            yearOfEntry,
            phone,
            password: placeholderPassword,
            status: 'pending',
            role: 'student',
            registrationTokenHash: hashToken(registrationToken),
            registrationTokenExpires: new Date(Date.now() + REGISTRATION_TTL_MS)
        } });
        res.status(200).json({ message: 'Step 1 saved!', registrationToken });
    } catch (err) {
        if (err.code === 'P2002') {
            return res.status(400).json({ message: 'ID is already registered.' });
        }
        res.status(500).json({ message: 'Registration could not be saved.' });
    }
});

app.post('/api/register-step2', registerLimiter, async (req, res) => {
    console.info('[REGISTER STEP2] Request received');
    try {
        const data = req.body || {};
        if (!data.universityId) {
            return res.status(400).json({ error: 'ID barataa hin argamne. Step 1 irraa deebi\'ii yaali.' });
        }

        const registrationFields = ['eName', 'ePhone', 'eRel', 'fName', 'fPhone', 'fRel'];
        if (registrationFields.some((field) => String(data[field] || '').length > 160)) {
            return res.status(400).json({ error: 'Emergency contact fields are too long.' });
        }
        if (!data.eName || !data.ePhone || !data.fName || !data.fPhone) {
            return res.status(400).json({ error: 'Emergency and family contact names and phone numbers are required.' });
        }

        console.info('[REGISTER STEP2] Registration data validated');
        const updatedUser = await assertRegistrationToken(data.universityId, data.registrationToken);

        const generatedPassword = cryptoRandomPassword();
        const hashedPw = await bcrypt.hash(generatedPassword, 12);
        const universityId = String(data.universityId).trim();
        const contactData = {
            eName: data.eName || '',
            ePhone: data.ePhone || '',
            eRel: data.eRel || '',
            fName: data.fName || '',
            fPhone: data.fPhone || '',
            fRel: data.fRel || ''
        };
        await prisma.$transaction([
            User.update({
                where: { id: updatedUser.id },
                data: { password: hashedPw, ...contactData }
            }),
            ContactEmergency.upsert({
                where: { universityId },
                update: contactData,
                create: {
                    universityId,
                    ...contactData
                }
            })
        ]);

        console.info('[REGISTER STEP2] User data saved');
        return res.status(200).json({
            message: 'Registration completed. Save your generated password to log in after admin approval.',
            registrationComplete: true,
            generatedPassword
        });
    } catch (err) {
        const status = Number(err.status) >= 400 && Number(err.status) < 600 ? Number(err.status) : 500;
        console.error(`[REGISTER STEP2] Failed status=${status}`);
        return res.status(status).json({ error: status === 500 ? 'Registration could not be completed because of a server error.' : err.message });
    }
});

function cryptoRandomPassword() {
    return String(crypto.randomInt(10000, 100000));
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
        await User.update({
            where: { id: user.id },
            data: {
                academicSkill: academicSkill || '',
                spiritualSkill: spiritualSkill || '',
                contribution: contribution || ''
            }
        });

        res.status(200).json({ message: 'Skills saved successfully.' });
    } catch (err) {
        res.status(err.status || 500).json({ message: err.message });
    }
});

app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const studentId = String(req.body.studentId || req.body.identifier || '').trim();
        const password = String(req.body.password || '');

        if (!studentId || !password) {
            return res.status(400).json({ message: 'Student ID and password are required.' });
        }

        const user = await User.findUnique({ where: { studentId } });
        if (!user) return res.status(400).json({ message: 'Student ID was not found.' });
        if (user.status === 'blocked') return res.status(403).json({ message: 'This account is blocked.' });
        if (user.status !== 'active') return res.status(403).json({ message: 'Admin mirkaneessuu eagi!' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Password dogoggora!' });

        const token = signUserToken(user);
        res.json({
            message: 'Success',
            name: user.name,
            role: String(user.role || '').toLowerCase(),
            studentId: user.studentId,
            profilePic: user.profilePic || '',
            token
        });
    } catch (err) {
        res.status(500).json({ message: 'Server Error' });
    }
});

app.post('/api/logout', authenticate, async (req, res) => {
    try {
        await User.update({
            where: { id: req.user.id },
            data: { tokenVersion: { increment: 1 } }
        });
        res.json({ message: 'Logged out successfully.' });
    } catch (err) {
        res.status(500).json({ message: 'Could not log out securely.' });
    }
});

app.get('/api/user/me', authenticate, async (req, res) => {
    try {
        const user = await User.findUnique({
            where: { id: req.user.id },
            select: {
                id: true, name: true, studentId: true, profilePic: true, role: true,
                status: true, profile: true, preferences: true, department: true,
                yearOfEntry: true, phone: true, createdAt: true
            }
        });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        res.json(toApiRecord(user));
    } catch (err) {
        res.status(500).json({ message: 'User profile could not be loaded.' });
    }
});

app.get('/api/user/settings', authenticate, async (req, res) => {
    try {
        const user = await User.findUnique({ where: { id: req.user.id } });
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
        const user = await User.findUnique({ where: { id: req.user.id } });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const fullName = String(req.body.fullName || user.profile?.fullName || user.name || '').trim();
        const phone = String(req.body.phone || user.profile?.phone || user.phone || '').trim();
        const department = String(req.body.department || user.department || '').trim();
        const yearOfEntry = String(req.body.yearOfEntry || user.yearOfEntry || '').trim();
        const profileImage = String(req.body.profileImage || req.body.profilePic || user.profile?.profileImage || user.profilePic || '').trim();

        if (!fullName) {
            return res.status(400).json({ message: 'Full name is required.' });
        }
        if (profileImage && !profileImage.startsWith('data:image/') && !/^https?:\/\//i.test(profileImage)) {
            return res.status(400).json({ message: 'Profile image must be a valid image URL or base64 image.' });
        }

        let updatedUser = user;
        if (user.role !== 'admin') {
            updatedUser = await User.update({
                where: { id: user.id },
                data: {
                    name: fullName,
                    phone,
                    department,
                    yearOfEntry,
                    profilePic: profileImage || user.profilePic || '',
                    profile: {
                        ...(user.profile || {}),
                        fullName,
                        phone,
                        profileImage: profileImage || user.profile?.profileImage || user.profilePic || ''
                    }
                }
            });
        }

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

        const user = await User.findUnique({ where: { id: req.user.id } });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Incorrect current password.' });
        }

        const updatedUser = await User.update({
            where: { id: user.id },
            data: {
                password: await bcrypt.hash(newPassword, 12),
                tokenVersion: { increment: 1 }
            }
        });

        const token = signUserToken(updatedUser);
        res.json({ message: 'Password changed successfully.', token });
    } catch (err) {
        res.status(500).json({ message: 'Password could not be changed.' });
    }
});

app.put('/api/user/settings/notifications', authenticate, async (req, res) => {
    try {
        const user = await User.findUnique({ where: { id: req.user.id } });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const previous = user.preferences || {};
        const preferences = {
            ...previous,
            eventNotifications: Boolean(req.body.eventNotifications ?? previous.eventNotifications ?? true),
            resourceNotifications: Boolean(req.body.resourceNotifications ?? previous.resourceNotifications ?? true),
            accountNotifications: Boolean(req.body.accountNotifications ?? previous.accountNotifications ?? true),
            systemNotifications: Boolean(req.body.systemNotifications ?? previous.systemNotifications ?? true),
            language: String(req.body.language || previous.language || 'en').trim() || 'en'
        };
        const updatedUser = await User.update({ where: { id: user.id }, data: { preferences } });

        res.json({
            message: 'Notification settings updated successfully.',
            settings: buildUserSettingsPayload(updatedUser)
        });
    } catch (err) {
        res.status(500).json({ message: 'Notification settings could not be updated.' });
    }
});

app.put('/api/user/settings/appearance', authenticate, async (req, res) => {
    try {
        const user = await User.findUnique({ where: { id: req.user.id } });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const previous = user.preferences || {};
        const preferences = {
            ...previous,
            darkMode: Boolean(req.body.darkMode ?? previous.darkMode ?? false),
            compactSidebar: Boolean(req.body.compactSidebar ?? previous.compactSidebar ?? false)
        };
        const updatedUser = await User.update({ where: { id: user.id }, data: { preferences } });

        res.json({
            message: 'Appearance settings updated successfully.',
            settings: buildUserSettingsPayload(updatedUser)
        });
    } catch (err) {
        res.status(500).json({ message: 'Appearance settings could not be updated.' });
    }
});

app.put('/api/user/settings/language', authenticate, async (req, res) => {
    try {
        const user = await User.findUnique({ where: { id: req.user.id } });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const language = String(req.body.language || '').trim().toLowerCase();
        if (!['en', 'om'].includes(language)) {
            return res.status(400).json({ message: 'Language preference is invalid.' });
        }

        const previous = user.preferences || {};
        const preferences = {
            ...previous,
            language
        };
        const updatedUser = await User.update({ where: { id: user.id }, data: { preferences } });

        res.json({
            message: 'Language preference updated successfully.',
            settings: buildUserSettingsPayload(updatedUser)
        });
    } catch (err) {
        res.status(500).json({ message: 'Language preference could not be updated.' });
    }
});

app.get('/api/admin/settings', authenticate, requireAdmin, async (req, res) => {
    try {
        const user = await User.findUnique({ where: { id: req.user.id } });
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
        const user = await User.findUnique({ where: { id: req.user.id } });
        if (!user) {
            return res.status(404).json({ message: 'Admin user not found.' });
        }

        const fullName = String(req.body.fullName || req.body.name || user.profile?.fullName || user.name || '').trim();
        const phone = String(req.body.phone || user.profile?.phone || user.phone || '').trim();
        const profileImage = String(req.body.profileImage || req.body.profilePic || user.profile?.profileImage || user.profilePic || '').trim();

        if (!fullName) {
            return res.status(400).json({ message: 'Admin full name is required.' });
        }
        if (profileImage && !profileImage.startsWith('data:image/') && !/^https?:\/\//i.test(profileImage)) {
            return res.status(400).json({ message: 'Profile image must be a valid image URL or base64 image.' });
        }

        const nextProfile = {
            ...(user.profile || {}),
            fullName,
            phone,
            profileImage
        };

        const updateData = {
            name: fullName,
            phone,
            profilePic: profileImage,
            profile: nextProfile,
            ...(phone || !user.phone ? {} : {})
        };

        const updatedUser = await User.update({
            where: { id: req.user.id },
            data: updateData
        });
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

        const user = await User.findUnique({ where: { id: req.user.id } });
        if (!user) {
            return res.status(404).json({ message: 'Admin user not found.' });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Current password is incorrect.' });
        }

        const updatedUser = await User.update({
            where: { id: user.id },
            data: {
                password: await bcrypt.hash(newPassword, 12),
                tokenVersion: { increment: 1 }
            }
        });

        const token = signUserToken(updatedUser);
        res.json({ message: 'Password changed successfully.', token });
    } catch (err) {
        res.status(500).json({ message: 'Password could not be changed.' });
    }
});

app.put('/api/admin/settings/notifications', authenticate, requireAdmin, async (req, res) => {
    try {
        const user = await User.findUnique({ where: { id: req.user.id } });
        if (!user) {
            return res.status(404).json({ message: 'Admin user not found.' });
        }

        const preferences = user.preferences || {};
        const updates = {
            registrationNotifications: Boolean(req.body.registrationNotifications ?? preferences.registrationNotifications ?? true),
            approvalNotifications: Boolean(req.body.approvalNotifications ?? preferences.approvalNotifications ?? true),
            systemNotifications: Boolean(req.body.systemNotifications ?? preferences.systemNotifications ?? true)
        };

        const nextPreferences = {
            ...preferences,
            ...updates
        };
        const updatedUser = await User.update({
            where: { id: user.id },
            data: { preferences: nextPreferences }
        });

        res.json({
            message: 'Notification settings updated.',
            settings: buildAdminSettingsPayload(updatedUser)
        });
    } catch (err) {
        res.status(500).json({ message: 'Notification settings could not be updated.' });
    }
});

app.put('/api/admin/settings/appearance', authenticate, requireAdmin, async (req, res) => {
    try {
        const user = await User.findUnique({ where: { id: req.user.id } });
        if (!user) {
            return res.status(404).json({ message: 'Admin user not found.' });
        }

        const preferences = user.preferences || {};
        const nextPreferences = {
            ...preferences,
            darkMode: Boolean(req.body.darkMode ?? preferences.darkMode ?? false),
            compactSidebar: Boolean(req.body.compactSidebar ?? preferences.compactSidebar ?? false)
        };

        const updatedUser = await User.update({
            where: { id: user.id },
            data: { preferences: nextPreferences }
        });

        res.json({
            message: 'Appearance settings updated.',
            settings: buildAdminSettingsPayload(updatedUser)
        });
    } catch (err) {
        res.status(500).json({ message: 'Appearance settings could not be updated.' });
    }
});

app.put('/api/admin/settings/logout-all-sessions', authenticate, requireAdmin, async (req, res) => {
    try {
        const user = await User.findUnique({ where: { id: req.user.id } });
        if (!user) {
            return res.status(404).json({ message: 'Admin user not found.' });
        }

        await User.update({
            where: { id: user.id },
            data: { tokenVersion: { increment: 1 } }
        });

        res.json({ message: 'All sessions were logged out successfully.' });
    } catch (err) {
        res.status(500).json({ message: 'Sessions could not be logged out.' });
    }
});

app.put('/api/user/profile-photo', authenticate, requireActive, async (req, res) => {
    try {
        const profilePic = String(req.body?.profilePic || '').trim();
        if (!profilePic) {
            return res.status(400).json({ message: 'Profile image is required.' });
        }
        if (profilePic.length > 800000) {
            return res.status(400).json({ message: 'Profile image is too large.' });
        }
        const imageMatch = profilePic.match(/^data:image\/(png|jpe?g|webp);base64,([A-Za-z0-9+/]+={0,2})$/i);
        if (!imageMatch) {
            return res.status(400).json({ message: 'Profile image must be a PNG, JPEG, or WebP image.' });
        }
        const imageBuffer = Buffer.from(imageMatch[2], 'base64');
        if (!imageBuffer.length || imageBuffer.length > 550 * 1024 || imageBuffer.toString('base64') !== imageMatch[2]) {
            return res.status(400).json({ message: 'Profile image must be 550 KB or smaller and contain valid image data.' });
        }

        const updatedUser = await User.update({
            where: { id: req.user.id },
            data: { profilePic },
            select: { profilePic: true }
        });

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

        const user = await User.findUnique({ where: { id: req.user.id } });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Current password is incorrect.' });
        }

        const updatedUser = await User.update({
            where: { id: user.id },
            data: {
                password: await bcrypt.hash(newPassword, 12),
                tokenVersion: { increment: 1 }
            }
        });

        const token = signUserToken(updatedUser);
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

        const created = await Message.create({ data: {
            studentId,
            studentName,
            content,
            isReadByUser: false
        } });

        res.status(201).json({ message: 'Comment sent to admin.', messageId: created.id });
    } catch (err) {
        res.status(500).json({ message: 'Message could not be sent.' });
    }
});

app.get('/api/user/messages', authenticate, requireActive, async (req, res) => {
    try {
        const studentId = String(req.user.studentId || '').trim();
        const rows = await Message.findMany({ where: { studentId }, orderBy: { createdAt: 'desc' } });
        const notifications = rows.filter((item) => item.reply && !item.isReadByUser);

        res.json({
            messages: rows.map(toApiRecord),
            unreadCount: notifications.length,
            notifications: notifications.map((item) => ({
                id: String(item.id),
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
        await Message.updateMany({
            where: { studentId, isReadByUser: false },
            data: { isReadByUser: true }
        });
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
        const deleted = await Message.deleteMany({
            where: {
                id: messageId,
                studentId
            }
        });

        if (deleted.count === 0) {
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
        const rows = await Message.findMany({ orderBy: { createdAt: 'desc' } });
        res.json({ messages: rows.map(toApiRecord) });
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
        if (reply.length > 4000) {
            return res.status(400).json({ message: 'Reply is too long.' });
        }

        const updated = await Message.updateMany({
            where: { id: messageId },
            data: { reply, isReadByUser: false, repliedAt: new Date() }
        });

        if (updated.count === 0) {
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

    if (department) filters.department = { equals: department };
    if (status && ALLOWED_STATUS.includes(status)) filters.status = status;
    if (role && ALLOWED_ROLES.includes(role)) filters.role = role;
    if (year) filters.yearOfEntry = { equals: year };
    if (search) {
        filters.OR = [
            { studentId: { contains: search } },
            { name: { contains: search } },
            { phone: { contains: search } }
        ];
    }

    return filters;
}

app.get('/api/admin/departments', authenticate, requireAdmin, async (req, res) => {
    try {
        const users = await User.findMany({ select: { department: true } });
        const departmentsByName = new Map();
        users.forEach(({ department }) => {
            const name = String(department || '').trim();
            if (!name) return;
            const key = name.toLowerCase();
            const entry = departmentsByName.get(key);
            if (entry) entry.count += 1;
            else departmentsByName.set(key, { department: name, count: 1 });
        });
        const departments = [...departmentsByName.values()]
            .sort((left, right) => left.department.localeCompare(right.department));

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
        const students = await User.findMany({
            where: filters,
            orderBy: { createdAt: 'desc' },
            select: { id: true, studentId: true, name: true, phone: true, yearOfEntry: true, status: true }
        });
        res.json(students.map(toApiRecord));
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
        const students = await User.findMany({
            where: buildAdminStudentFilters(req.query),
            orderBy: { createdAt: 'desc' },
            select: {
                studentId: true, name: true, phone: true, department: true, yearOfEntry: true,
                eName: true, ePhone: true, eRel: true, fName: true, fPhone: true, fRel: true,
                academicSkill: true, spiritualSkill: true, contribution: true, role: true,
                status: true, createdAt: true
            }
        });
        const contactIds = students
            .filter((student) => !student.eName && !student.ePhone && !student.fName && !student.fPhone)
            .map((student) => student.studentId)
            .filter(Boolean);
        const contacts = contactIds.length
            ? await ContactEmergency.findMany({ where: { universityId: { in: contactIds } } })
            : [];
        const contactsById = new Map(contacts.map((contact) => [String(contact.universityId), contact]));
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Students', { views: [{ state: 'frozen', ySplit: 1 }] });
        worksheet.columns = [
            { header: 'Student ID', key: 'studentId' },
            { header: 'Full Name', key: 'fullName' },
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
            { header: 'Registration Date', key: 'registrationDate' }
        ];
        students.forEach((student) => {
            const contact = contactsById.get(String(student.studentId)) || {};
            worksheet.addRow({
                studentId: student.studentId || '',
                fullName: student.name || '',
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
                registrationDate: student.createdAt || null
            });
        });
        worksheet.autoFilter = { from: 'A1', to: `M${Math.max(students.length + 1, 1)}` };
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
        const students = await User.findMany({
            where: buildAdminStudentFilters(req.query),
            orderBy: { createdAt: 'desc' },
            select: {
                id: true, studentId: true, name: true, gender: true, department: true, yearOfEntry: true,
                phone: true, role: true, status: true, eName: true, ePhone: true, eRel: true,
                fName: true, fPhone: true, fRel: true, academicSkill: true,
                spiritualSkill: true, contribution: true, createdAt: true
            }
        });

        const contactIds = students
            .filter((student) => !student.eName && !student.ePhone && !student.fName && !student.fPhone)
            .map((student) => student.studentId)
            .filter(Boolean);
        const contacts = contactIds.length
            ? await ContactEmergency.findMany({
                where: { universityId: { in: contactIds } },
                select: {
                    universityId: true, eName: true, ePhone: true, eRel: true,
                    fName: true, fPhone: true, fRel: true
                }
            })
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

        res.json(merged.map(toApiRecord));
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
        const target = await User.findFirst({ where: { studentId: rawId } });

        if (!target) {
            return res.status(404).json({ message: 'Barataan hin argamne' });
        }
        if (String(target.id) === String(req.user.id)) {
            return res.status(400).json({ message: 'You cannot delete your own account from this screen.' });
        }
        if (target.role === 'admin' && (await countAdmins()) <= 1) {
            return res.status(400).json({ message: 'Cannot delete the last admin account.' });
        }

        await User.delete({ where: { id: target.id } });
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

        const target = await User.findFirst({ where: { studentId } });
        if (!target) {
            return res.status(404).json({ message: 'Barataan hin argamne' });
        }
        const updatedUser = await User.update({
            where: { id: target.id },
            data: { status: 'active', tokenVersion: { increment: 1 } }
        });

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

        const target = await User.findUnique({ where: { studentId } });
        if (!target) {
            return res.status(404).json({ message: 'Barataan hin argamne' });
        }
        if (String(target.id) === String(req.user.id)) {
            return res.status(400).json({ message: 'You cannot block your own account.' });
        }

        const updatedUser = await User.update({
            where: { id: target.id },
            data: { status: 'blocked', tokenVersion: { increment: 1 } }
        });

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

        const existingUser = await User.findUnique({ where: { studentId } });
        if (existingUser) {
            return res.status(400).json({ error: 'Student ID already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        await User.create({ data: {
            studentId,
            name,
            password: hashedPassword,
            status,
            role
        } });
        res.status(200).json({ message: "Barataan galmaa'eera" });
    } catch (err) {
        res.status(500).json({ error: 'Student could not be added.' });
    }
});

let latestNews = "there is no announcement.";

app.post('/api/admin/news', authenticate, requireAdmin, (req, res) => {
    latestNews = String(req.body.news || '');
    res.json({ message: 'News updated' });
});

app.get('/api/news', authenticate, requireActive, (req, res) => {
    res.json({ news: latestNews });
});

app.get('/api/admin/stats', authenticate, requireAdmin, async (req, res) => {
    try {
        res.json(await getStudentStatistics(true));
    } catch (err) {
        console.error('Admin statistics error:', err);
        res.status(500).json({ message: 'Statistics could not be loaded.' });
    }
});

app.get('/api/statistics', authenticate, requireActive, async (req, res) => {
    try {
        res.json(await getStudentStatistics(false));
    } catch (err) {
        res.status(500).json({ message: "Statistics hin fe'amne" });
    }
});

async function getStudentStatistics(includePending) {
    const where = { role: 'student' };
    const [total, active, pending, genderCounts] = await Promise.all([
        User.count({ where }),
        User.count({ where: { ...where, status: 'active' } }),
        includePending ? User.count({ where: { ...where, status: 'pending' } }) : Promise.resolve(0),
        User.groupBy({ by: ['gender'], where, _count: { _all: true } })
    ]);
    const countsByGender = new Map(genderCounts.map((row) => [row.gender, row._count._all]));
    return {
        total,
        active,
        ...(includePending ? { pending } : {}),
        male: countsByGender.get('Male') || 0,
        female: countsByGender.get('Female') || 0
    };
}

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
        await User.update({
            where: { id: req.user.id },
            data: { profilePic: '' }
        });
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

        const user = await User.findUnique({ where: { studentId } });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        if (String(user.id) === String(req.user.id) && newRole !== 'admin') {
            return res.status(400).json({ message: 'You cannot remove your own admin role.' });
        }
        if (user.role === 'admin' && newRole !== 'admin' && (await countAdmins()) <= 1) {
            return res.status(400).json({ message: 'Cannot demote the last admin.' });
        }

        await User.update({
            where: { id: user.id },
            data: { role: newRole, tokenVersion: { increment: 1 } }
        });

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
        const status = req.body.status;
        const role = req.body.role;

        if (!studentId) {
            return res.status(400).json({ message: 'Student ID is required.' });
        }

        const user = await User.findUnique({ where: { studentId } });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const updateData = {};
        if (name) updateData.name = String(name).trim();
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
            if (String(user.id) === String(req.user.id) && role !== 'admin') {
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

        if (Object.keys(updateData).length > 0) {
            await User.update({
                where: { studentId },
                data: updateData
            });
        }
        res.json({ message: 'User information updated successfully.' });
    } catch (err) {
        console.error('Update user error:', err);
        res.status(500).json({ message: 'Error updating user information: ' + err.message });
    }
});

app.put('/api/admin/reset-password', authenticate, requireAdmin, async (req, res) => {
    try {
        const studentId = String(req.body.studentId || '').trim();
        if (!studentId) {
            return res.status(400).json({ message: 'Student ID is required.' });
        }

        const generatedPassword = cryptoRandomPassword();
        const hashedPassword = await bcrypt.hash(generatedPassword, 12);
        const user = await User.update({
            where: { studentId },
            data: { password: hashedPassword, tokenVersion: { increment: 1 } },
            select: { studentId: true }
        });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.json({
            message: 'Password reset successfully.',
            generatedPassword
        });
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
    res.status(500).json({ message: 'Unexpected server error.' })
});

if (require.main === module) {
    app.listen(PORT, '0.0.0.0', () => console.log(`Server on port ${PORT}`));
}

module.exports = app;
