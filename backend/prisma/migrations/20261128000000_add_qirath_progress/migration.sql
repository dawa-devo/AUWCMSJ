CREATE TABLE `ProgressEntry` (
    `_id` VARCHAR(191) NOT NULL,
    `student` VARCHAR(160) NOT NULL,
    `studentId` VARCHAR(80) NOT NULL,
    `level` VARCHAR(32) NOT NULL,
    `detail` TEXT NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `ProgressEntry_studentId_createdAt_idx`(`studentId`, `createdAt`),
    INDEX `ProgressEntry_createdAt_idx`(`createdAt`),
    PRIMARY KEY (`_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
