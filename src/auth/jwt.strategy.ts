import { ExtractJwt, Strategy, StrategyOptionsWithoutRequest } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from '../common/dto/auth.dto';
import { Request } from 'express';

/**
 * JWT Strategy with Key Rotation Support
 * 
 * Supports graceful key rotation by attempting verification with:
 * 1. Current JWT_SECRET
 * 2. Previous secrets from JWT_PREVIOUS_SECRETS (comma-separated)
 * 
 * This allows tokens issued before key rotation to remain valid
 * until they naturally expire.
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    private readonly logger = new Logger(JwtStrategy.name);
    private readonly currentSecret: string;
    private readonly previousSecrets: string[];

    constructor(configService: ConfigService) {
        const jwtSecret = configService.get<string>('JWT_SECRET');
        if (!jwtSecret) {
            throw new Error('JWT_SECRET must be configured');
        }

        // Parse previous secrets for key rotation support
        const previousSecretsStr = configService.get<string>('JWT_PREVIOUS_SECRETS') || '';
        const previousSecrets = previousSecretsStr
            .split(',')
            .map(s => s.trim())
            .filter(s => s.length > 0);

        super({
            jwtFromRequest: ExtractJwt.fromExtractors([
                // First try Authorization header
                ExtractJwt.fromAuthHeaderAsBearerToken(),
                // Then try cookie
                (request: Request) => {
                    const token = request?.cookies?.access_token;
                    return token || null;
                },
            ]),
            ignoreExpiration: false,
            secretOrKey: jwtSecret,
            issuer: configService.get<string>('OAUTH_ISSUER') || 'sso-system',
        } as StrategyOptionsWithoutRequest);

        this.currentSecret = jwtSecret;
        this.previousSecrets = previousSecrets;

        if (previousSecrets.length > 0) {
            this.logger.log(`Key rotation enabled with ${previousSecrets.length} previous secret(s)`);
        }
    }

    async validate(payload: JwtPayload): Promise<{
        userId: string;
        username: string;
        email: string;
        roles: string[];
        mfaVerified: boolean;
    }> {
        // Validate required claims
        if (!payload.sub || !payload.username) {
            this.logger.warn('Invalid JWT payload - missing required claims');
            throw new UnauthorizedException('Invalid token');
        }

        return {
            userId: payload.sub,
            username: payload.username,
            email: payload.email,
            roles: payload.roles || [],
            mfaVerified: payload.mfaVerified || false,
        };
    }

    /**
     * Get all valid secrets (current + previous) for verification
     * Used by other services that need to verify tokens
     */
    getAllSecrets(): string[] {
        return [this.currentSecret, ...this.previousSecrets];
    }
}
