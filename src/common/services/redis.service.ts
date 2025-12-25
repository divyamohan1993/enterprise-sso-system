import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

/**
 * Redis Service for session storage, caching, and rate limiting
 * 
 * Provides:
 * - Refresh token storage
 * - Authorization code storage
 * - Session management
 * - Rate limit counters
 */
@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
    private readonly logger = new Logger(RedisService.name);
    private client: Redis | null = null;
    private isConnected = false;

    // Key prefixes for namespacing
    private readonly PREFIX = {
        REFRESH_TOKEN: 'rt:',
        AUTH_CODE: 'ac:',
        SESSION: 'session:',
        RATE_LIMIT: 'rl:',
        MFA_ATTEMPT: 'mfa:',
        BLACKLIST: 'bl:',
    };

    constructor(private readonly configService: ConfigService) { }

    async onModuleInit(): Promise<void> {
        const redisHost = this.configService.get<string>('REDIS_HOST');

        if (!redisHost) {
            this.logger.warn('Redis not configured - using in-memory fallback');
            return;
        }

        try {
            this.client = new Redis({
                host: redisHost,
                port: this.configService.get<number>('REDIS_PORT') || 6379,
                password: this.configService.get<string>('REDIS_PASSWORD') || undefined,
                retryStrategy: (times: number) => {
                    if (times > 3) {
                        this.logger.error('Redis connection failed after 3 retries');
                        return null; // Stop retrying
                    }
                    return Math.min(times * 200, 2000);
                },
                maxRetriesPerRequest: 3,
            });

            this.client.on('connect', () => {
                this.isConnected = true;
                this.logger.log('🔴 Redis connected successfully');
            });

            this.client.on('error', (err) => {
                this.isConnected = false;
                this.logger.error(`Redis error: ${err.message}`);
            });

            this.client.on('close', () => {
                this.isConnected = false;
                this.logger.warn('Redis connection closed');
            });

        } catch (error) {
            this.logger.error(`Failed to connect to Redis: ${error}`);
        }
    }

    async onModuleDestroy(): Promise<void> {
        if (this.client) {
            await this.client.quit();
            this.logger.log('Redis connection closed');
        }
    }

    /**
     * Check if Redis is available
     */
    isAvailable(): boolean {
        return this.isConnected && this.client !== null;
    }

    // ========================================
    // REFRESH TOKEN MANAGEMENT
    // ========================================

    async storeRefreshToken(
        jti: string,
        userId: string,
        expiresInSeconds: number
    ): Promise<void> {
        if (!this.isAvailable()) return;

        const key = `${this.PREFIX.REFRESH_TOKEN}${jti}`;
        await this.client!.setex(key, expiresInSeconds, JSON.stringify({
            userId,
            createdAt: Date.now(),
        }));
    }

    async getRefreshToken(jti: string): Promise<{ userId: string; createdAt: number } | null> {
        if (!this.isAvailable()) return null;

        const key = `${this.PREFIX.REFRESH_TOKEN}${jti}`;
        const data = await this.client!.get(key);

        if (!data) return null;
        return JSON.parse(data);
    }

    async revokeRefreshToken(jti: string): Promise<void> {
        if (!this.isAvailable()) return;

        const key = `${this.PREFIX.REFRESH_TOKEN}${jti}`;
        await this.client!.del(key);
    }

    async revokeAllUserTokens(userId: string): Promise<void> {
        if (!this.isAvailable()) return;

        const pattern = `${this.PREFIX.REFRESH_TOKEN}*`;
        const keys = await this.client!.keys(pattern);

        for (const key of keys) {
            const data = await this.client!.get(key);
            if (data) {
                const parsed = JSON.parse(data);
                if (parsed.userId === userId) {
                    await this.client!.del(key);
                }
            }
        }
    }

    // ========================================
    // AUTHORIZATION CODE MANAGEMENT
    // ========================================

    async storeAuthCode(
        code: string,
        data: {
            userId: string;
            clientId: string;
            redirectUri: string;
            scope: string;
            codeChallenge?: string;
            codeChallengeMethod?: string;
        },
        expiresInSeconds: number = 600 // 10 minutes
    ): Promise<void> {
        if (!this.isAvailable()) return;

        const key = `${this.PREFIX.AUTH_CODE}${code}`;
        await this.client!.setex(key, expiresInSeconds, JSON.stringify({
            ...data,
            createdAt: Date.now(),
        }));
    }

    async getAuthCode(code: string): Promise<{
        userId: string;
        clientId: string;
        redirectUri: string;
        scope: string;
        codeChallenge?: string;
        codeChallengeMethod?: string;
        createdAt: number;
    } | null> {
        if (!this.isAvailable()) return null;

        const key = `${this.PREFIX.AUTH_CODE}${code}`;
        const data = await this.client!.get(key);

        if (!data) return null;
        return JSON.parse(data);
    }

    async consumeAuthCode(code: string): Promise<boolean> {
        if (!this.isAvailable()) return false;

        const key = `${this.PREFIX.AUTH_CODE}${code}`;
        const result = await this.client!.del(key);
        return result > 0;
    }

    // ========================================
    // TOKEN BLACKLIST
    // ========================================

    async blacklistToken(jti: string, expiresInSeconds: number): Promise<void> {
        if (!this.isAvailable()) return;

        const key = `${this.PREFIX.BLACKLIST}${jti}`;
        await this.client!.setex(key, expiresInSeconds, '1');
    }

    async isTokenBlacklisted(jti: string): Promise<boolean> {
        if (!this.isAvailable()) return false;

        const key = `${this.PREFIX.BLACKLIST}${jti}`;
        const result = await this.client!.exists(key);
        return result > 0;
    }

    // ========================================
    // MFA ATTEMPT TRACKING
    // ========================================

    async trackMfaAttempt(userId: string): Promise<number> {
        if (!this.isAvailable()) return 0;

        const key = `${this.PREFIX.MFA_ATTEMPT}${userId}`;
        const attempts = await this.client!.incr(key);

        // Set TTL on first attempt (15 minutes window)
        if (attempts === 1) {
            await this.client!.expire(key, 900);
        }

        return attempts;
    }

    async getMfaAttempts(userId: string): Promise<number> {
        if (!this.isAvailable()) return 0;

        const key = `${this.PREFIX.MFA_ATTEMPT}${userId}`;
        const attempts = await this.client!.get(key);
        return attempts ? parseInt(attempts, 10) : 0;
    }

    async resetMfaAttempts(userId: string): Promise<void> {
        if (!this.isAvailable()) return;

        const key = `${this.PREFIX.MFA_ATTEMPT}${userId}`;
        await this.client!.del(key);
    }

    // ========================================
    // GENERIC OPERATIONS
    // ========================================

    async set(key: string, value: string, expiresInSeconds?: number): Promise<void> {
        if (!this.isAvailable()) return;

        if (expiresInSeconds) {
            await this.client!.setex(key, expiresInSeconds, value);
        } else {
            await this.client!.set(key, value);
        }
    }

    async get(key: string): Promise<string | null> {
        if (!this.isAvailable()) return null;
        return this.client!.get(key);
    }

    async del(key: string): Promise<void> {
        if (!this.isAvailable()) return;
        await this.client!.del(key);
    }

    async exists(key: string): Promise<boolean> {
        if (!this.isAvailable()) return false;
        const result = await this.client!.exists(key);
        return result > 0;
    }

    // ========================================
    // HEALTH CHECK
    // ========================================

    async ping(): Promise<boolean> {
        if (!this.client) return false;

        try {
            const result = await this.client.ping();
            return result === 'PONG';
        } catch {
            return false;
        }
    }
}
