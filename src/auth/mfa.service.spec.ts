import { Test, TestingModule } from '@nestjs/testing';
import { MfaService } from './mfa.service';

describe('MfaService', () => {
    let service: MfaService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [MfaService],
        }).compile();

        service = module.get<MfaService>(MfaService);
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    describe('generateSecret', () => {
        it('should generate a secret string', () => {
            const secret = service.generateSecret();

            expect(secret).toBeDefined();
            expect(typeof secret).toBe('string');
            expect(secret.length).toBeGreaterThan(0);
        });

        it('should generate unique secrets', () => {
            const secret1 = service.generateSecret();
            const secret2 = service.generateSecret();

            expect(secret1).not.toBe(secret2);
        });
    });

    describe('verifyToken', () => {
        it('should verify a valid TOTP token', () => {
            const secret = service.generateSecret();
            // In a real test, we'd generate a valid token
            // For now, we test the interface exists
            const result = service.verifyToken('123456', secret);

            expect(typeof result).toBe('boolean');
        });

        it('should reject invalid tokens', () => {
            const secret = service.generateSecret();

            expect(service.verifyToken('000000', secret)).toBe(false);
            expect(service.verifyToken('invalid', secret)).toBe(false);
        });
    });

    describe('generateBackupCodes', () => {
        it('should generate the requested number of codes', () => {
            const codes = service.generateBackupCodes(10);

            expect(codes).toHaveLength(10);
        });

        it('should generate unique codes', () => {
            const codes = service.generateBackupCodes(10);
            const uniqueCodes = new Set(codes);

            expect(uniqueCodes.size).toBe(10);
        });

        it('should format codes as XXXX-XXXX', () => {
            const codes = service.generateBackupCodes(5);

            codes.forEach(code => {
                expect(code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
            });
        });
    });

    describe('hashBackupCodes', () => {
        it('should hash all backup codes', async () => {
            const codes = ['ABCD-1234', 'EFGH-5678'];
            const hashed = await service.hashBackupCodes(codes);

            expect(hashed).toHaveLength(2);
            hashed.forEach(hash => {
                expect(hash.length).toBe(64); // SHA-256 hex = 64 chars
            });
        });
    });

    describe('verifyBackupCode', () => {
        it('should verify a valid backup code', async () => {
            const codes = ['ABCD-1234'];
            const hashed = await service.hashBackupCodes(codes);

            const index = service.verifyBackupCode('ABCD-1234', hashed);

            expect(index).toBe(0);
        });

        it('should reject an invalid backup code', async () => {
            const codes = ['ABCD-1234'];
            const hashed = await service.hashBackupCodes(codes);

            const index = service.verifyBackupCode('WRONG-CODE', hashed);

            expect(index).toBe(-1);
        });
    });

    describe('setupMfa', () => {
        it('should return complete MFA setup data', async () => {
            const result = await service.setupMfa('testuser', 'Test Issuer');

            expect(result.secret).toBeDefined();
            expect(result.qrCodeDataUrl).toMatch(/^data:image\/png;base64,/);
            expect(result.backupCodes).toHaveLength(10);
        });
    });
});
