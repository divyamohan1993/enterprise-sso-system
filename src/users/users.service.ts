import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { User, UserRole, UserStatus } from './user.entity';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';

export interface CreateUserDto {
    username: string;
    email: string;
    password: string;
    roles?: UserRole[];
    firstName?: string;
    lastName?: string;
}

export interface SecurityContext {
    ip: string;
    userAgent: string;
    correlationId?: string;
}

// Constants for security
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 30;
const PASSWORD_HISTORY_COUNT = 5;

@Injectable()
export class UsersService implements OnModuleInit {
    private readonly logger = new Logger(UsersService.name);

    // In-memory fallback for development (when DB is not connected)
    private inMemoryUsers: Map<string, User> = new Map();

    async onModuleInit(): Promise<void> {
        // Check if default admin exists, if not create one
        await this.ensureDefaultAdmin();
    }

    /**
     * Ensure a default admin user exists for initial setup
     */
    private async ensureDefaultAdmin(): Promise<void> {
        const adminExists = await this.findByUsername('admin');

        if (!adminExists) {
            // Generate a secure random password for first-time setup
            const defaultPassword = process.env.ADMIN_INITIAL_PASSWORD ||
                crypto.randomBytes(16).toString('base64');

            const admin = await this.create({
                username: 'admin',
                email: 'admin@sso-enterprise.local',
                password: defaultPassword,
                roles: [UserRole.SUPER_ADMIN],
                firstName: 'System',
                lastName: 'Administrator',
            });

            // Mark as active immediately for initial setup
            admin.status = UserStatus.ACTIVE;
            admin.emailVerified = true;
            await this.save(admin);

            this.logger.warn(`
╔══════════════════════════════════════════════════════════════╗
║  🔐 DEFAULT ADMIN CREATED                                     ║
║  Username: admin                                              ║
║  Password: ${defaultPassword.padEnd(40)}     ║
║                                                               ║
║  ⚠️  CHANGE THIS PASSWORD IMMEDIATELY IN PRODUCTION!         ║
╚══════════════════════════════════════════════════════════════╝
            `);
        }
    }

    /**
     * Create a new user with proper password hashing
     */
    async create(dto: CreateUserDto): Promise<User> {
        const user = new User();
        user.id = crypto.randomUUID();
        user.username = dto.username.toLowerCase().trim();
        user.email = dto.email.toLowerCase().trim();
        user.password = await this.hashPassword(dto.password);
        user.roles = dto.roles || [UserRole.USER];
        user.status = UserStatus.PENDING_VERIFICATION;
        user.firstName = dto.firstName || null;
        user.lastName = dto.lastName || null;
        user.createdAt = new Date();
        user.updatedAt = new Date();
        user.passwordChangedAt = new Date();
        user.passwordHistory = [user.password];

        await this.save(user);
        return user;
    }

    /**
     * Find user by username
     */
    async findByUsername(username: string): Promise<User | null> {
        const normalizedUsername = username.toLowerCase().trim();
        return this.inMemoryUsers.get(normalizedUsername) || null;
    }

    /**
     * Find user by email
     */
    async findByEmail(email: string): Promise<User | null> {
        const normalizedEmail = email.toLowerCase().trim();

        for (const user of this.inMemoryUsers.values()) {
            if (user.email === normalizedEmail) {
                return user;
            }
        }
        return null;
    }

    /**
     * Find user by ID
     */
    async findById(id: string): Promise<User | null> {
        for (const user of this.inMemoryUsers.values()) {
            if (user.id === id) {
                return user;
            }
        }
        return null;
    }

    /**
     * Validate user credentials with proper security checks
     */
    async validateCredentials(
        username: string,
        password: string,
        context?: SecurityContext
    ): Promise<{ user: User | null; requiresMfa: boolean; error?: string }> {
        const user = await this.findByUsername(username);

        if (!user) {
            // Don't reveal if user exists
            this.logger.warn(`Login attempt for non-existent user: ${username}`, {
                ip: context?.ip,
                correlationId: context?.correlationId,
            });
            return { user: null, requiresMfa: false, error: 'Invalid credentials' };
        }

        // Check if account is locked
        if (user.isLocked()) {
            const remainingMinutes = Math.ceil(
                (user.lockedUntil!.getTime() - Date.now()) / 60000
            );
            this.logger.warn(`Login attempt on locked account: ${username}`, {
                ip: context?.ip,
                remainingMinutes,
            });
            return {
                user: null,
                requiresMfa: false,
                error: `Account locked. Try again in ${remainingMinutes} minutes.`
            };
        }

        // Check if account is active
        if (user.status !== UserStatus.ACTIVE) {
            return { user: null, requiresMfa: false, error: 'Account is not active' };
        }

        // Verify password
        const isValidPassword = await this.verifyPassword(password, user.password);

        if (!isValidPassword) {
            await this.recordFailedLogin(user, context);
            return { user: null, requiresMfa: false, error: 'Invalid credentials' };
        }

        // Reset failed attempts on successful login
        await this.resetFailedAttempts(user);

        // Check if MFA is required
        if (user.mfaEnabled) {
            return { user, requiresMfa: true };
        }

        // Update last login info
        await this.recordSuccessfulLogin(user, context);

        return { user, requiresMfa: false };
    }

    /**
     * Hash password using Argon2id (recommended by OWASP)
     */
    private async hashPassword(password: string): Promise<string> {
        return argon2.hash(password, {
            type: argon2.argon2id,
            memoryCost: 65536,  // 64 MB
            timeCost: 3,        // 3 iterations
            parallelism: 4,     // 4 threads
        });
    }

    /**
     * Verify password against hash
     */
    private async verifyPassword(password: string, hash: string): Promise<boolean> {
        try {
            return await argon2.verify(hash, password);
        } catch {
            return false;
        }
    }

    /**
     * Record failed login attempt
     */
    private async recordFailedLogin(user: User, context?: SecurityContext): Promise<void> {
        user.failedLoginAttempts += 1;

        if (user.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
            user.lockedUntil = new Date(Date.now() + LOCKOUT_DURATION_MINUTES * 60 * 1000);
            this.logger.warn(`Account locked due to failed attempts: ${user.username}`, {
                attempts: user.failedLoginAttempts,
                lockedUntil: user.lockedUntil,
                ip: context?.ip,
            });
        }

        await this.save(user);
    }

    /**
     * Reset failed login attempts
     */
    private async resetFailedAttempts(user: User): Promise<void> {
        if (user.failedLoginAttempts > 0) {
            user.failedLoginAttempts = 0;
            user.lockedUntil = null;
            await this.save(user);
        }
    }

    /**
     * Record successful login
     */
    private async recordSuccessfulLogin(user: User, context?: SecurityContext): Promise<void> {
        user.lastLoginAt = new Date();
        user.lastLoginIp = context?.ip || null;
        await this.save(user);
    }

    /**
     * Change user password with history check
     */
    async changePassword(
        user: User,
        newPassword: string
    ): Promise<{ success: boolean; error?: string }> {
        // Check password history
        if (user.passwordHistory) {
            for (const oldHash of user.passwordHistory) {
                if (await argon2.verify(oldHash, newPassword)) {
                    return {
                        success: false,
                        error: `Cannot reuse last ${PASSWORD_HISTORY_COUNT} passwords`
                    };
                }
            }
        }

        // Hash new password
        const newHash = await this.hashPassword(newPassword);

        // Update password history
        const history = user.passwordHistory || [];
        history.push(newHash);
        if (history.length > PASSWORD_HISTORY_COUNT) {
            history.shift(); // Remove oldest
        }

        user.password = newHash;
        user.passwordHistory = history;
        user.passwordChangedAt = new Date();

        await this.save(user);
        return { success: true };
    }

    /**
     * Enable MFA for user
     */
    async enableMfa(user: User, secret: string, backupCodes: string[]): Promise<void> {
        user.mfaEnabled = true;
        user.mfaSecret = secret;
        user.mfaBackupCodes = backupCodes;
        await this.save(user);
    }

    /**
     * Disable MFA for user
     */
    async disableMfa(user: User): Promise<void> {
        user.mfaEnabled = false;
        user.mfaSecret = null;
        user.mfaBackupCodes = null;
        await this.save(user);
    }

    /**
     * Save user to storage
     */
    private async save(user: User): Promise<void> {
        user.updatedAt = new Date();
        this.inMemoryUsers.set(user.username, user);
    }
}
