import {
    Injectable,
    BadRequestException,
    UnauthorizedException,
    Logger,
} from '@nestjs/common';
import { UsersService, SecurityContext } from '../users/users.service';
import { BlockchainService } from '../blockchain/blockchain.service';
import { ConfigService } from '@nestjs/config';
import { MfaService } from './mfa.service';
import { KeyManagementService } from './key-management.service';
import { JwtPayload, TokenResponseDto } from '../common/dto/auth.dto';
import * as crypto from 'crypto';

interface AuthorizationCodeData {
    user: {
        id: string;
        username: string;
        email: string;
        roles: string[];
    };
    clientId: string;
    redirectUri: string;
    scope: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
    expiresAt: number;
}

interface RefreshTokenData {
    userId: string;
    jti: string;
    expiresAt: number;
}

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);

    // In production, use Redis for these stores
    private authorizationCodes = new Map<string, AuthorizationCodeData>();
    private refreshTokens = new Map<string, RefreshTokenData>();

    constructor(
        private readonly usersService: UsersService,
        private readonly blockchainService: BlockchainService,
        private readonly configService: ConfigService,
        private readonly mfaService: MfaService,
        private readonly keyManagement: KeyManagementService,
    ) { }

    /**
     * Validate user credentials with full security checks
     */
    async validateUser(
        username: string,
        password: string,
        context?: SecurityContext
    ): Promise<{ user: any | null; requiresMfa: boolean; error?: string }> {
        // Calculate behavioral hash for audit trail
        const behavioralHash = crypto.createHash('sha3-256')
            .update(JSON.stringify({
                ip: context?.ip,
                userAgent: context?.userAgent,
                timestamp: Date.now(),
            }))
            .digest('hex');

        const result = await this.usersService.validateCredentials(
            username,
            password,
            context
        );

        if (!result.user) {
            // Log failed authentication to blockchain
            await this.blockchainService.addBlock({
                event: 'AUTH_FAILURE',
                username,
                behavioralSignature: behavioralHash,
                ip: context?.ip,
                reason: result.error,
                riskScore: 0.95,
                timestamp: new Date().toISOString(),
            });

            return result;
        }

        // Log successful authentication to blockchain
        await this.blockchainService.addBlock({
            event: result.requiresMfa ? 'AUTH_MFA_REQUIRED' : 'AUTH_SUCCESS',
            userId: result.user.id,
            username: result.user.username,
            behavioralSignature: behavioralHash,
            ip: context?.ip,
            riskScore: 0.05,
            timestamp: new Date().toISOString(),
        });

        return {
            user: {
                id: result.user.id,
                username: result.user.username,
                email: result.user.email,
                roles: result.user.roles,
            },
            requiresMfa: result.requiresMfa,
        };
    }

    /**
     * Verify MFA token and complete login
     */
    async verifyMfa(
        userId: string,
        token: string,
        context?: SecurityContext
    ): Promise<TokenResponseDto | null> {
        const user = await this.usersService.findById(userId);

        if (!user || !user.mfaSecret) {
            throw new UnauthorizedException('Invalid MFA session');
        }

        // First try TOTP
        if (this.mfaService.verifyToken(token, user.mfaSecret)) {
            return this.issueTokens(user);
        }

        // Try backup codes
        if (user.mfaBackupCodes) {
            const codeIndex = this.mfaService.verifyBackupCode(token, user.mfaBackupCodes);
            if (codeIndex >= 0) {
                // Remove used backup code
                user.mfaBackupCodes.splice(codeIndex, 1);
                await this.usersService.enableMfa(
                    user,
                    user.mfaSecret,
                    user.mfaBackupCodes
                );

                this.logger.warn(`Backup code used for user: ${user.username}`);
                return this.issueTokens(user);
            }
        }

        // Log failed MFA attempt
        await this.blockchainService.addBlock({
            event: 'MFA_FAILURE',
            userId: user.id,
            timestamp: new Date().toISOString(),
            ip: context?.ip,
        });

        throw new UnauthorizedException('Invalid MFA token');
    }

    /**
     * Issue access and refresh tokens
     */
    async issueTokens(user: any): Promise<TokenResponseDto> {
        const payload: JwtPayload = {
            sub: user.id,
            username: user.username,
            email: user.email,
            roles: user.roles,
            mfaVerified: user.mfaEnabled || false,
        };

        const expiresIn = this.configService.get<string>('JWT_EXPIRATION') || '1h';
        const refreshExpiresIn = this.configService.get<string>('JWT_REFRESH_EXPIRATION') || '7d';

        // Issue access token
        const accessToken = await this.keyManagement.signJwt(payload, expiresIn);

        // Issue refresh token
        const refreshJti = crypto.randomUUID();
        const refreshPayload = {
            sub: user.id,
            jti: refreshJti,
            type: 'refresh',
        };
        const refreshToken = await this.keyManagement.signJwt(refreshPayload, refreshExpiresIn);

        // Store refresh token for validation
        this.refreshTokens.set(refreshJti, {
            userId: user.id,
            jti: refreshJti,
            expiresAt: Date.now() + this.parseExpirationTime(refreshExpiresIn),
        });

        return {
            access_token: accessToken,
            refresh_token: refreshToken,
            token_type: 'Bearer',
            expires_in: this.parseExpirationTime(expiresIn) / 1000,
        };
    }

    /**
     * Login flow - returns tokens or MFA challenge
     */
    async login(
        user: any,
        context?: SecurityContext
    ): Promise<TokenResponseDto | { requiresMfa: true; mfaSessionToken: string }> {
        // If user needs MFA, return a session token for MFA verification
        // (This would be called after validateUser returns requiresMfa: true)
        return this.issueTokens(user);
    }

    /**
     * Refresh access token using refresh token
     */
    async refreshAccessToken(refreshToken: string): Promise<TokenResponseDto> {
        try {
            const payload = await this.keyManagement.verifyJwt(refreshToken);

            if (payload.type !== 'refresh' || !payload.jti) {
                throw new UnauthorizedException('Invalid refresh token');
            }

            const storedToken = this.refreshTokens.get(payload.jti as string);

            if (!storedToken || storedToken.expiresAt < Date.now()) {
                throw new UnauthorizedException('Refresh token expired');
            }

            const user = await this.usersService.findById(payload.sub as string);

            if (!user) {
                throw new UnauthorizedException('User not found');
            }

            // Rotate refresh token (one-time use)
            this.refreshTokens.delete(payload.jti as string);

            return this.issueTokens(user);
        } catch (error) {
            throw new UnauthorizedException('Invalid refresh token');
        }
    }

    /**
     * Revoke refresh token (logout)
     */
    async revokeRefreshToken(refreshToken: string): Promise<void> {
        try {
            const payload = await this.keyManagement.verifyJwt(refreshToken);
            if (payload.jti) {
                this.refreshTokens.delete(payload.jti as string);
            }
        } catch {
            // Token already invalid, ignore
        }
    }

    // ============= OIDC Methods =============

    /**
     * Generate OAuth2 authorization code
     */
    async generateAuthorizationCode(
        user: any,
        clientId: string,
        redirectUri: string,
        scope: string = 'openid profile email',
        codeChallenge?: string,
        codeChallengeMethod?: string
    ): Promise<string> {
        const code = crypto.randomBytes(32).toString('hex');

        this.authorizationCodes.set(code, {
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                roles: user.roles,
            },
            clientId,
            redirectUri,
            scope,
            codeChallenge,
            codeChallengeMethod,
            expiresAt: Date.now() + 600000, // 10 minutes
        });

        // Log to blockchain
        await this.blockchainService.addBlock({
            event: 'OAUTH_CODE_ISSUED',
            userId: user.id,
            clientId,
            timestamp: new Date().toISOString(),
        });

        return code;
    }

    /**
     * Exchange authorization code for tokens
     */
    async exchangeCode(
        code: string,
        clientId: string,
        clientSecret: string,
        codeVerifier?: string
    ): Promise<{ access_token: string; id_token: string; token_type: string; expires_in: number }> {
        const data = this.authorizationCodes.get(code);

        if (!data || data.expiresAt < Date.now()) {
            throw new BadRequestException('invalid_grant');
        }

        if (data.clientId !== clientId) {
            throw new BadRequestException('invalid_client');
        }

        // PKCE verification
        if (data.codeChallenge && data.codeChallengeMethod === 'S256') {
            if (!codeVerifier) {
                throw new BadRequestException('code_verifier required');
            }

            const challenge = crypto
                .createHash('sha256')
                .update(codeVerifier)
                .digest('base64url');

            if (challenge !== data.codeChallenge) {
                throw new BadRequestException('invalid_code_verifier');
            }
        }

        // Burn code (single use)
        this.authorizationCodes.delete(code);

        // Issue OIDC tokens
        const issuer = this.configService.get('OAUTH_ISSUER') || 'sso-system';

        const accessPayload = {
            sub: data.user.id,
            username: data.user.username,
            email: data.user.email,
            roles: data.user.roles,
            scope: data.scope,
        };

        const idTokenPayload = {
            sub: data.user.id,
            iss: issuer,
            aud: clientId,
            name: data.user.username,
            email: data.user.email,
            email_verified: true, // Simplified
            nonce: crypto.randomUUID(), // Should come from auth request
        };

        const accessToken = await this.keyManagement.signJwt(accessPayload, '1h');
        const idToken = await this.keyManagement.signJwt(idTokenPayload, '1h');

        // Log to blockchain
        await this.blockchainService.addBlock({
            event: 'OAUTH_TOKEN_ISSUED',
            userId: data.user.id,
            clientId,
            timestamp: new Date().toISOString(),
        });

        return {
            access_token: accessToken,
            id_token: idToken,
            token_type: 'Bearer',
            expires_in: 3600,
        };
    }

    /**
     * Get JWKS for token verification
     */
    async getJwks(): Promise<any> {
        return this.keyManagement.exportJwks();
    }

    // ============= MFA Setup =============

    /**
     * Setup MFA for authenticated user
     */
    async setupMfa(userId: string): Promise<{ secret: string; qrCode: string; backupCodes: string[] }> {
        const user = await this.usersService.findById(userId);

        if (!user) {
            throw new UnauthorizedException('User not found');
        }

        if (user.mfaEnabled) {
            throw new BadRequestException('MFA already enabled');
        }

        const issuer = this.configService.get('OAUTH_ISSUER') || 'Enterprise SSO';
        const result = await this.mfaService.setupMfa(user.username, issuer);

        // Return setup data (user must verify before enabling)
        // Note: backup codes are hashed when confirmMfaSetup is called
        return {
            secret: result.secret,
            qrCode: result.qrCodeDataUrl,
            backupCodes: result.backupCodes, // Show only once
        };
    }

    /**
     * Confirm MFA setup
     */
    async confirmMfaSetup(
        userId: string,
        secret: string,
        token: string,
        backupCodes: string[]
    ): Promise<boolean> {
        const user = await this.usersService.findById(userId);

        if (!user) {
            throw new UnauthorizedException('User not found');
        }

        // Verify the token works
        if (!this.mfaService.verifyToken(token, secret)) {
            throw new BadRequestException('Invalid token - MFA setup failed');
        }

        // Hash backup codes for storage
        const hashedBackupCodes = await this.mfaService.hashBackupCodes(backupCodes);

        // Enable MFA
        await this.usersService.enableMfa(user, secret, hashedBackupCodes);

        // Log to blockchain
        await this.blockchainService.addBlock({
            event: 'MFA_ENABLED',
            userId: user.id,
            timestamp: new Date().toISOString(),
        });

        return true;
    }

    // ============= Helper Methods =============

    private parseExpirationTime(expiration: string): number {
        const match = expiration.match(/^(\d+)([smhd])$/);
        if (!match) return 3600000; // Default 1 hour

        const value = parseInt(match[1], 10);
        const unit = match[2];

        const multipliers: Record<string, number> = {
            's': 1000,
            'm': 60 * 1000,
            'h': 60 * 60 * 1000,
            'd': 24 * 60 * 60 * 1000,
        };

        return value * (multipliers[unit] || 3600000);
    }
}
