import { Injectable, Logger } from '@nestjs/common';
import { authenticator } from 'otplib';
import * as QRCode from 'qrcode';
import * as crypto from 'crypto';

export interface MfaSetupResult {
    secret: string;
    qrCodeDataUrl: string;
    backupCodes: string[];
}

@Injectable()
export class MfaService {
    private readonly logger = new Logger(MfaService.name);

    constructor() {
        // Configure TOTP settings
        authenticator.options = {
            window: 1, // Allow 1 step before/after for clock drift
            step: 30,  // 30 second validity window
            digits: 6, // 6 digit codes
        };
    }

    /**
     * Generate a new MFA secret for user setup
     */
    generateSecret(): string {
        return authenticator.generateSecret(32); // 32 bytes = 256 bits
    }

    /**
     * Generate QR code for authenticator app
     */
    async generateQrCode(username: string, secret: string, issuer: string = 'Enterprise SSO'): Promise<string> {
        const otpAuthUrl = authenticator.keyuri(username, issuer, secret);

        try {
            return await QRCode.toDataURL(otpAuthUrl, {
                errorCorrectionLevel: 'H',
                type: 'image/png',
                margin: 2,
                width: 256,
            });
        } catch (error) {
            this.logger.error(`Failed to generate QR code: ${error}`);
            throw new Error('Failed to generate QR code');
        }
    }

    /**
     * Verify a TOTP token
     */
    verifyToken(token: string, secret: string): boolean {
        try {
            return authenticator.verify({ token, secret });
        } catch (error) {
            this.logger.warn(`Token verification error: ${error}`);
            return false;
        }
    }

    /**
     * Generate backup codes for MFA recovery
     * Returns 10 single-use codes
     */
    generateBackupCodes(count: number = 10): string[] {
        const codes: string[] = [];
        const usedCodes = new Set<string>();

        while (codes.length < count) {
            // Generate 8-character alphanumeric codes (grouped as XXXX-XXXX)
            const code = this.generateSecureCode();
            const formattedCode = `${code.slice(0, 4)}-${code.slice(4, 8)}`.toUpperCase();

            if (!usedCodes.has(formattedCode)) {
                usedCodes.add(formattedCode);
                codes.push(formattedCode);
            }
        }

        return codes;
    }

    /**
     * Hash backup codes for secure storage
     */
    async hashBackupCodes(codes: string[]): Promise<string[]> {
        return codes.map(code =>
            crypto.createHash('sha256').update(code.replace('-', '')).digest('hex')
        );
    }

    /**
     * Verify a backup code against stored hashes
     * Returns the index of the matched code or -1 if not found
     */
    verifyBackupCode(code: string, hashedCodes: string[]): number {
        const normalizedCode = code.replace('-', '').toUpperCase();
        const codeHash = crypto.createHash('sha256').update(normalizedCode).digest('hex');

        return hashedCodes.findIndex(hash => hash === codeHash);
    }

    /**
     * Complete MFA setup flow
     */
    async setupMfa(username: string, issuer?: string): Promise<MfaSetupResult> {
        const secret = this.generateSecret();
        const qrCodeDataUrl = await this.generateQrCode(username, secret, issuer);
        const backupCodes = this.generateBackupCodes(10);

        return {
            secret,
            qrCodeDataUrl,
            backupCodes,
        };
    }

    /**
     * Generate a cryptographically secure random code
     */
    private generateSecureCode(): string {
        const bytes = crypto.randomBytes(5); // 5 bytes = 10 hex chars, we use 8
        return bytes.toString('hex').slice(0, 8);
    }
}
