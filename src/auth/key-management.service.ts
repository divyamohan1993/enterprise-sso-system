import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as jose from 'jose';
import * as crypto from 'crypto';

interface KeyPair {
    publicKey: jose.CryptoKey;
    privateKey: jose.CryptoKey;
    kid: string;
    alg: string;
}

/**
 * RSA/ECDSA Key Management Service for JWT signing
 * Generates asymmetric keys on startup for proper OIDC compliance
 */
@Injectable()
export class KeyManagementService implements OnModuleInit {
    private readonly logger = new Logger(KeyManagementService.name);
    private keys: Map<string, KeyPair> = new Map();
    private currentKeyId: string = '';

    async onModuleInit(): Promise<void> {
        await this.rotateKeys();
        this.logger.log('🔐 Key Management Service initialized with ECDSA keys');
    }

    /**
     * Generate new key pair and set as current
     */
    async rotateKeys(): Promise<void> {
        const kid = this.generateKid();

        // Using ES256 (ECDSA with P-256) for better performance than RSA
        const { publicKey, privateKey } = await jose.generateKeyPair('ES256', {
            extractable: true,
        });

        this.keys.set(kid, {
            publicKey: publicKey as jose.CryptoKey,
            privateKey: privateKey as jose.CryptoKey,
            kid,
            alg: 'ES256',
        });

        this.currentKeyId = kid;
        this.logger.log(`🔑 Generated new key pair with KID: ${kid}`);

        // Cleanup old keys (keep last 2 for token validation during rotation)
        this.pruneOldKeys(2);
    }

    /**
     * Get current signing key
     */
    getCurrentKey(): KeyPair | undefined {
        return this.keys.get(this.currentKeyId);
    }

    /**
     * Get key by ID (for verification)
     */
    getKey(kid: string): KeyPair | undefined {
        return this.keys.get(kid);
    }

    /**
     * Sign a JWT payload
     */
    async signJwt(payload: jose.JWTPayload, expiresIn: string = '1h'): Promise<string> {
        const key = this.getCurrentKey();
        if (!key) {
            throw new Error('No signing key available');
        }

        const jwt = await new jose.SignJWT(payload)
            .setProtectedHeader({ alg: key.alg, kid: key.kid })
            .setIssuedAt()
            .setExpirationTime(expiresIn)
            .setJti(crypto.randomUUID())
            .sign(key.privateKey);

        return jwt;
    }

    /**
     * Verify a JWT
     */
    async verifyJwt(token: string): Promise<jose.JWTPayload> {
        // Try to decode header to get kid
        const header = jose.decodeProtectedHeader(token);
        const kid = header.kid;

        let publicKey: jose.CryptoKey;

        if (kid && this.keys.has(kid)) {
            publicKey = this.keys.get(kid)!.publicKey;
        } else {
            // Fallback to current key
            const currentKey = this.getCurrentKey();
            if (!currentKey) {
                throw new Error('No verification key available');
            }
            publicKey = currentKey.publicKey;
        }

        const { payload } = await jose.jwtVerify(token, publicKey);
        return payload;
    }

    /**
     * Export JWKS for /.well-known/jwks.json endpoint
     */
    async exportJwks(): Promise<jose.JSONWebKeySet> {
        const keys: jose.JWK[] = [];

        for (const [kid, keyPair] of this.keys) {
            const jwk = await jose.exportJWK(keyPair.publicKey);
            keys.push({
                ...jwk,
                kid,
                alg: keyPair.alg,
                use: 'sig',
            });
        }

        return { keys };
    }

    /**
     * Generate a unique key ID
     */
    private generateKid(): string {
        return `key-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    }

    /**
     * Remove old keys, keeping the specified count
     */
    private pruneOldKeys(keepCount: number): void {
        const allKids = Array.from(this.keys.keys());
        if (allKids.length <= keepCount) return;

        // Sort by timestamp in kid (older first)
        const toRemove = allKids
            .sort()
            .slice(0, allKids.length - keepCount);

        toRemove.forEach(kid => {
            this.keys.delete(kid);
            this.logger.log(`🗑️ Pruned old key: ${kid}`);
        });
    }
}
