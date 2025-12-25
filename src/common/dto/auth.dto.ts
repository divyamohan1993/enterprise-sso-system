import { IsString, IsEmail, IsNotEmpty, MinLength, MaxLength, Matches, IsOptional } from 'class-validator';
import { Transform } from 'class-transformer';

/**
 * Login Request DTO with strict validation
 */
export class LoginDto {
    @IsString()
    @IsNotEmpty()
    @MinLength(3)
    @MaxLength(50)
    @Transform(({ value }) => value?.trim().toLowerCase())
    username: string;

    @IsString()
    @IsNotEmpty()
    @MinLength(8)
    @MaxLength(128)
    password: string;

    @IsOptional()
    @IsString()
    @Matches(/^[0-9]{6}$/, { message: 'MFA token must be 6 digits' })
    mfaToken?: string;
}

/**
 * Registration Request DTO
 */
export class RegisterDto {
    @IsString()
    @IsNotEmpty()
    @MinLength(3)
    @MaxLength(50)
    @Matches(/^[a-zA-Z0-9_-]+$/, { message: 'Username can only contain letters, numbers, underscores and hyphens' })
    @Transform(({ value }) => value?.trim().toLowerCase())
    username: string;

    @IsEmail()
    @IsNotEmpty()
    @MaxLength(255)
    @Transform(({ value }) => value?.trim().toLowerCase())
    email: string;

    @IsString()
    @IsNotEmpty()
    @MinLength(12, { message: 'Password must be at least 12 characters for enterprise security' })
    @MaxLength(128)
    @Matches(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/,
        { message: 'Password must contain uppercase, lowercase, number and special character' }
    )
    password: string;

    @IsString()
    @IsNotEmpty()
    confirmPassword: string;

    @IsOptional()
    @IsString()
    @MaxLength(50)
    firstName?: string;

    @IsOptional()
    @IsString()
    @MaxLength(50)
    lastName?: string;
}

/**
 * Token Exchange DTO (OAuth)
 */
export class TokenExchangeDto {
    @IsString()
    @IsNotEmpty()
    grant_type: string;

    @IsString()
    @IsNotEmpty()
    code: string;

    @IsString()
    @IsNotEmpty()
    client_id: string;

    @IsString()
    @IsNotEmpty()
    client_secret: string;

    @IsString()
    @IsNotEmpty()
    redirect_uri: string;
}

/**
 * MFA Setup Response
 */
export class MfaSetupResponseDto {
    secret: string;
    qrCode: string;
    backupCodes: string[];
}

/**
 * MFA Verification DTO
 */
export class MfaVerifyDto {
    @IsString()
    @IsNotEmpty()
    @Matches(/^[0-9]{6}$/, { message: 'Token must be 6 digits' })
    token: string;
}

/**
 * Password Change DTO
 */
export class ChangePasswordDto {
    @IsString()
    @IsNotEmpty()
    currentPassword: string;

    @IsString()
    @IsNotEmpty()
    @MinLength(12)
    @MaxLength(128)
    @Matches(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/,
        { message: 'Password must contain uppercase, lowercase, number and special character' }
    )
    newPassword: string;

    @IsString()
    @IsNotEmpty()
    confirmNewPassword: string;
}

/**
 * Refresh Token DTO
 */
export class RefreshTokenDto {
    @IsString()
    @IsNotEmpty()
    refreshToken: string;
}

/**
 * JWT Payload Interface
 * Compatible with jose library JWTPayload
 */
export interface JwtPayload {
    sub: string;
    username: string;
    email: string;
    roles: string[];
    mfaVerified: boolean;
    iat?: number;
    exp?: number;
    jti?: string;
    // Index signature for jose library compatibility
    [key: string]: unknown;
}

/**
 * Token Response
 */
export class TokenResponseDto {
    access_token: string;
    refresh_token?: string;
    token_type: string = 'Bearer';
    expires_in: number;
    scope?: string;
}
