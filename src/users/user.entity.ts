import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, BeforeInsert, BeforeUpdate } from 'typeorm';
import * as argon2 from 'argon2';

export enum UserRole {
    USER = 'user',
    ADMIN = 'admin',
    SUPER_ADMIN = 'super_admin'
}

export enum UserStatus {
    ACTIVE = 'active',
    INACTIVE = 'inactive',
    LOCKED = 'locked',
    PENDING_VERIFICATION = 'pending_verification'
}

@Entity('users')
export class User {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({ unique: true, length: 255 })
    username: string;

    @Column({ unique: true, length: 255 })
    email: string;

    @Column({ select: false })
    password: string;

    @Column({ type: 'simple-array', default: UserRole.USER })
    roles: UserRole[];

    @Column({ type: 'enum', enum: UserStatus, default: UserStatus.PENDING_VERIFICATION })
    status: UserStatus;

    // MFA Fields
    @Column({ nullable: true, select: false })
    mfaSecret: string | null;

    @Column({ default: false })
    mfaEnabled: boolean;

    @Column({ type: 'simple-array', nullable: true, select: false })
    mfaBackupCodes: string[] | null;

    // Security Fields
    @Column({ default: 0 })
    failedLoginAttempts: number;

    @Column({ type: 'timestamp', nullable: true })
    lockedUntil: Date | null;

    @Column({ type: 'timestamp', nullable: true })
    lastLoginAt: Date | null;

    @Column({ nullable: true })
    lastLoginIp: string | null;

    // Password Policy
    @Column({ type: 'timestamp', nullable: true })
    passwordChangedAt: Date | null;

    @Column({ type: 'simple-array', nullable: true, select: false })
    passwordHistory: string[] | null; // Store last N password hashes

    // Audit Fields
    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;

    @Column({ nullable: true })
    createdBy: string | null;

    // Profile Fields
    @Column({ nullable: true })
    firstName: string | null;

    @Column({ nullable: true })
    lastName: string | null;

    @Column({ nullable: true })
    avatarUrl: string | null;

    @Column({ default: false })
    emailVerified: boolean;

    // Methods
    @BeforeInsert()
    @BeforeUpdate()
    async hashPassword() {
        if (this.password && !this.password.startsWith('$argon2')) {
            this.password = await argon2.hash(this.password, {
                type: argon2.argon2id,
                memoryCost: 65536,
                timeCost: 3,
                parallelism: 4
            });
        }
    }

    async validatePassword(plainPassword: string): Promise<boolean> {
        try {
            return await argon2.verify(this.password, plainPassword);
        } catch {
            return false;
        }
    }

    isLocked(): boolean {
        if (!this.lockedUntil) return false;
        return new Date() < this.lockedUntil;
    }

    getFullName(): string {
        return [this.firstName, this.lastName].filter(Boolean).join(' ') || this.username;
    }
}
