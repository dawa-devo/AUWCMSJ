-- CreateTable
CREATE TABLE `User` (
    `_id` VARCHAR(191) NOT NULL,
    `studentId` VARCHAR(80) NOT NULL,
    `name` VARCHAR(160) NOT NULL,
    `gender` VARCHAR(191) NOT NULL DEFAULT '',
    `department` VARCHAR(191) NOT NULL DEFAULT '',
    `yearOfEntry` VARCHAR(191) NOT NULL DEFAULT '',
    `phone` VARCHAR(191) NOT NULL DEFAULT '',
    `profilePic` MEDIUMTEXT NOT NULL DEFAULT '',
    `profile` JSON NULL,
    `preferences` JSON NULL,
    `password` VARCHAR(255) NOT NULL,
    `role` VARCHAR(191) NOT NULL DEFAULT 'student',
    `status` VARCHAR(191) NOT NULL DEFAULT 'pending',
    `registrationTokenHash` VARCHAR(255) NOT NULL DEFAULT '',
    `registrationTokenExpires` DATETIME(3) NULL,
    `tokenVersion` INTEGER NOT NULL DEFAULT 0,
    `eName` VARCHAR(160) NULL,
    `ePhone` VARCHAR(160) NULL,
    `eRel` VARCHAR(160) NULL,
    `fName` VARCHAR(160) NULL,
    `fPhone` VARCHAR(160) NULL,
    `fRel` VARCHAR(160) NULL,
    `academicSkill` TEXT NULL,
    `spiritualSkill` TEXT NULL,
    `contribution` TEXT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `User_studentId_key`(`studentId`),
    INDEX `User_role_createdAt_idx`(`role`, `createdAt`),
    INDEX `User_role_status_createdAt_idx`(`role`, `status`, `createdAt`),
    INDEX `User_role_gender_idx`(`role`, `gender`),
    INDEX `User_createdAt_idx`(`createdAt`),
    PRIMARY KEY (`_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Resource` (
    `_id` VARCHAR(191) NOT NULL,
    `title` TEXT NULL,
    `category` VARCHAR(191) NULL,
    `fileName` VARCHAR(255) NULL,
    `fileUrl` TEXT NULL,
    `publicId` VARCHAR(191) NULL,
    `resourceType` VARCHAR(191) NULL,
    `mimeType` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (`_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Message` (
    `_id` VARCHAR(191) NOT NULL,
    `studentId` VARCHAR(80) NOT NULL,
    `studentName` VARCHAR(191) NOT NULL DEFAULT '',
    `content` TEXT NOT NULL,
    `reply` TEXT NOT NULL DEFAULT '',
    `isReadByUser` BOOLEAN NOT NULL DEFAULT false,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `repliedAt` DATETIME(3) NULL,

    INDEX `Message_studentId_idx`(`studentId`),
    PRIMARY KEY (`_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ContactEmergency` (
    `_id` VARCHAR(191) NOT NULL,
    `universityId` VARCHAR(80) NOT NULL,
    `eName` VARCHAR(191) NULL,
    `ePhone` VARCHAR(191) NULL,
    `eRel` VARCHAR(191) NULL,
    `fName` VARCHAR(191) NULL,
    `fPhone` VARCHAR(191) NULL,
    `fRel` VARCHAR(191) NULL,

    UNIQUE INDEX `ContactEmergency_universityId_key`(`universityId`),
    PRIMARY KEY (`_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
