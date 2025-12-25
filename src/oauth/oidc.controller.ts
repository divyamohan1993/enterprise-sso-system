import { Controller, Get, Query, Res, UseGuards, Req, Post, Body, BadRequestException } from '@nestjs/common';
import { Response, Request } from 'express';
import { AuthService } from '../auth/auth.service';
import { ConfigService } from '@nestjs/config';
import { AuthGuard } from '@nestjs/passport';

interface AuthenticatedRequest extends Request {
    user: {
        userId: string;
        username: string;
        email?: string;
    };
}

@Controller('oauth')
export class OidcController {
    constructor(
        private authService: AuthService,
        private configService: ConfigService
    ) { }

    @Get('.well-known/openid-configuration')
    getDiscovery(@Req() req: Request) {
        const baseUrl = `${req.protocol}://${req.get('host')}`;
        return {
            issuer: baseUrl,
            authorization_endpoint: `${baseUrl}/oauth/authorize`,
            token_endpoint: `${baseUrl}/oauth/token`,
            userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
            jwks_uri: `${baseUrl}/oauth/jwks`,
            response_types_supported: ['code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['RS256', 'ES256'],
            scopes_supported: ['openid', 'profile', 'email']
        };
    }

    @Get('jwks')
    async getJwks() {
        // Use standard RS256/ES256 JWKS from AuthService (which manages keys)
        return this.authService.getJwks();
    }

    @Get('authorize')
    async authorize(
        @Query('response_type') responseType: string,
        @Query('client_id') clientId: string,
        @Query('redirect_uri') redirectUri: string,
        @Query('scope') scope: string,
        @Query('state') state: string,
        @Res() res: Response
    ) {
        // 1. Validate Client
        const validClient = this.configService.get('OAUTH_CLIENT_ID') || 'default_client';
        const validRedirect = this.configService.get('OAUTH_REDIRECT_URI') || 'http://localhost:3000/callback';

        if (clientId !== validClient) {
            return res.status(400).json({ error: 'invalid_client' });
        }
        // Strict redirect URI matching
        if (!redirectUri || !redirectUri.startsWith(validRedirect)) {
            return res.status(400).json({ error: 'invalid_redirect_uri' });
        }

        // 2. Redirect to internal LOGIN page (hosted by this SSO)
        // For this API-first implementation, we'll redirect to a static login page or handle it via a 
        // strictly defined flow. For automation, let's assume we render a login form or 
        // check session. 

        // DEMO: If not logged in, show login. If logged in, generating code.
        // In a real app, verify cookie.

        // We direct them to the actual login endpoint with state preserved
        // This is a simplification. Real OIDC persists this request in DB.
        return res.redirect(`/auth/login-page?redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&client_id=${clientId}`);
    }

    @Post('token')
    async token(
        @Body('grant_type') grantType: string,
        @Body('code') code: string,
        @Body('client_id') clientId: string,
        @Body('client_secret') clientSecret: string,
        @Body('redirect_uri') redirectUri: string
    ) {
        if (grantType !== 'authorization_code') {
            throw new BadRequestException('unsupported_grant_type');
        }
        // Exchange Code for Tokens
        return this.authService.exchangeCode(code, clientId, clientSecret);
    }

    @UseGuards(AuthGuard('jwt'))
    @Get('userinfo')
    getUserInfo(@Req() req: AuthenticatedRequest) {
        return {
            sub: req.user.userId,
            name: req.user.username,
            email: req.user.email || 'user@example.com',
            // Add other OIDC claims
        };
    }
}
