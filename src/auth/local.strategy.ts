import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Request } from 'express';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
    private readonly logger = new Logger(LocalStrategy.name);

    constructor(private authService: AuthService) {
        super({
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: true, // Pass request to validate for context
        });
    }

    async validate(req: Request, username: string, password: string): Promise<any> {
        // Extract security context from request
        const context = {
            ip: req.ip || req.socket.remoteAddress || 'unknown',
            userAgent: req.headers['user-agent'] || 'unknown',
            correlationId: (req as any).correlationId,
        };

        const result = await this.authService.validateUser(username, password, context);

        if (!result.user) {
            this.logger.warn(`Authentication failed for user: ${username}`, {
                ip: context.ip,
                correlationId: context.correlationId,
            });
            throw new UnauthorizedException(result.error || 'Invalid credentials');
        }

        // If MFA is required, we still return the user but flag it
        // The controller will handle the MFA flow
        if (result.requiresMfa) {
            return {
                ...result.user,
                requiresMfa: true,
            };
        }

        return result.user;
    }
}
