import {
    Controller,
    Request,
    Post,
    UseGuards,
    Get,
    Body,
    HttpCode,
    HttpStatus,
    Ip,
    Headers,
    BadRequestException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Throttle } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { LoginDto, MfaVerifyDto, RefreshTokenDto, ChangePasswordDto } from '../common/dto/auth.dto';
import { UsersService } from '../users/users.service';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly usersService: UsersService,
    ) { }

    /**
     * Login endpoint with rate limiting
     * Returns tokens or MFA challenge
     */
    @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 attempts per minute
    @Post('login')
    @HttpCode(HttpStatus.OK)
    async login(
        @Body() loginDto: LoginDto,
        @Ip() ip: string,
        @Headers('user-agent') userAgent: string,
        @Request() req: any,
    ) {
        const context = {
            ip,
            userAgent: userAgent || 'unknown',
            correlationId: req.correlationId,
        };

        const result = await this.authService.validateUser(
            loginDto.username,
            loginDto.password,
            context,
        );

        if (!result.user) {
            throw new BadRequestException(result.error || 'Invalid credentials');
        }

        // If MFA is required and token provided, verify it
        if (result.requiresMfa) {
            if (loginDto.mfaToken) {
                return this.authService.verifyMfa(
                    result.user.id,
                    loginDto.mfaToken,
                    context,
                );
            }

            // Return MFA challenge
            return {
                requiresMfa: true,
                message: 'MFA verification required',
                // In production, return a temporary session token
            };
        }

        // Issue tokens
        return this.authService.login(result.user, context);
    }

    /**
     * Verify MFA token
     */
    @Throttle({ default: { limit: 5, ttl: 60000 } })
    @Post('mfa/verify')
    @HttpCode(HttpStatus.OK)
    async verifyMfa(
        @Body() body: MfaVerifyDto & { userId: string },
        @Ip() ip: string,
    ) {
        return this.authService.verifyMfa(body.userId, body.token, { ip, userAgent: '' });
    }

    /**
     * Refresh access token
     */
    @Throttle({ default: { limit: 10, ttl: 60000 } })
    @Post('refresh')
    @HttpCode(HttpStatus.OK)
    async refreshToken(@Body() body: RefreshTokenDto) {
        return this.authService.refreshAccessToken(body.refreshToken);
    }

    /**
     * Logout - revoke refresh token
     */
    @Post('logout')
    @HttpCode(HttpStatus.NO_CONTENT)
    async logout(@Body() body: RefreshTokenDto) {
        await this.authService.revokeRefreshToken(body.refreshToken);
    }

    /**
     * Get current user profile
     */
    @UseGuards(AuthGuard('jwt'))
    @Get('profile')
    getProfile(@Request() req: any) {
        return {
            id: req.user.userId,
            username: req.user.username,
            roles: req.user.roles,
        };
    }

    /**
     * Setup MFA for current user
     */
    @UseGuards(AuthGuard('jwt'))
    @Post('mfa/setup')
    async setupMfa(@Request() req: any) {
        return this.authService.setupMfa(req.user.userId);
    }

    /**
     * Confirm MFA setup with verification token
     */
    @UseGuards(AuthGuard('jwt'))
    @Post('mfa/confirm')
    async confirmMfa(
        @Request() req: any,
        @Body() body: { secret: string; token: string; backupCodes: string[] },
    ) {
        const success = await this.authService.confirmMfaSetup(
            req.user.userId,
            body.secret,
            body.token,
            body.backupCodes,
        );

        return { success, message: 'MFA enabled successfully' };
    }

    /**
     * Change password
     */
    @UseGuards(AuthGuard('jwt'))
    @Throttle({ default: { limit: 3, ttl: 60000 } })
    @Post('change-password')
    @HttpCode(HttpStatus.OK)
    async changePassword(
        @Request() req: any,
        @Body() body: ChangePasswordDto,
    ) {
        if (body.newPassword !== body.confirmNewPassword) {
            throw new BadRequestException('Passwords do not match');
        }

        const user = await this.usersService.findById(req.user.userId);
        if (!user) {
            throw new BadRequestException('User not found');
        }

        // Verify current password
        const validation = await this.usersService.validateCredentials(
            user.username,
            body.currentPassword,
        );

        if (!validation.user) {
            throw new BadRequestException('Current password is incorrect');
        }

        // Change password
        const result = await this.usersService.changePassword(user, body.newPassword);

        if (!result.success) {
            throw new BadRequestException(result.error);
        }

        return { message: 'Password changed successfully' };
    }
}
