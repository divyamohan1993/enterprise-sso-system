import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { ConfigService } from '@nestjs/config';
import { BlockchainService } from '../blockchain/blockchain.service';
import { MfaService } from './mfa.service';
import { KeyManagementService } from './key-management.service';

describe('AuthService', () => {
    let service: AuthService;
    let usersService: jest.Mocked<UsersService>;
    let blockchainService: jest.Mocked<BlockchainService>;
    let keyManagement: jest.Mocked<KeyManagementService>;

    const mockUser = {
        id: 'test-user-id',
        username: 'testuser',
        email: 'test@example.com',
        roles: ['user'],
        mfaEnabled: false,
    };

    beforeEach(async () => {
        const mockUsersService = {
            validateCredentials: jest.fn(),
            findById: jest.fn(),
            findByUsername: jest.fn(),
            enableMfa: jest.fn(),
        };

        const mockBlockchainService = {
            addBlock: jest.fn().mockResolvedValue({}),
        };

        const mockMfaService = {
            verifyToken: jest.fn(),
            verifyBackupCode: jest.fn(),
            setupMfa: jest.fn(),
            hashBackupCodes: jest.fn(),
        };

        const mockKeyManagement = {
            signJwt: jest.fn().mockResolvedValue('mock-jwt-token'),
            verifyJwt: jest.fn(),
            exportJwks: jest.fn().mockResolvedValue({ keys: [] }),
        };

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                AuthService,
                { provide: UsersService, useValue: mockUsersService },
                { provide: ConfigService, useValue: { get: jest.fn().mockReturnValue('1h') } },
                { provide: BlockchainService, useValue: mockBlockchainService },
                { provide: MfaService, useValue: mockMfaService },
                { provide: KeyManagementService, useValue: mockKeyManagement },
            ],
        }).compile();

        service = module.get<AuthService>(AuthService);
        usersService = module.get(UsersService);
        blockchainService = module.get(BlockchainService);
        keyManagement = module.get(KeyManagementService);
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    describe('validateUser', () => {
        it('should return user when credentials are valid', async () => {
            usersService.validateCredentials.mockResolvedValue({
                user: mockUser as any,
                requiresMfa: false,
            });

            const result = await service.validateUser('testuser', 'password123', {
                ip: '127.0.0.1',
                userAgent: 'test-agent',
            });

            expect(result.user).toBeDefined();
            expect(result.user.username).toBe('testuser');
            expect(result.requiresMfa).toBe(false);
            expect(blockchainService.addBlock).toHaveBeenCalledWith(
                expect.objectContaining({ event: 'AUTH_SUCCESS' })
            );
        });

        it('should return null when credentials are invalid', async () => {
            usersService.validateCredentials.mockResolvedValue({
                user: null,
                requiresMfa: false,
                error: 'Invalid credentials',
            });

            const result = await service.validateUser('testuser', 'wrongpassword', {
                ip: '127.0.0.1',
                userAgent: 'test-agent',
            });

            expect(result.user).toBeNull();
            expect(blockchainService.addBlock).toHaveBeenCalledWith(
                expect.objectContaining({ event: 'AUTH_FAILURE' })
            );
        });

        it('should return requiresMfa when MFA is enabled', async () => {
            usersService.validateCredentials.mockResolvedValue({
                user: { ...mockUser, mfaEnabled: true } as any,
                requiresMfa: true,
            });

            const result = await service.validateUser('testuser', 'password123', {
                ip: '127.0.0.1',
                userAgent: 'test-agent',
            });

            expect(result.requiresMfa).toBe(true);
            expect(blockchainService.addBlock).toHaveBeenCalledWith(
                expect.objectContaining({ event: 'AUTH_MFA_REQUIRED' })
            );
        });
    });

    describe('issueTokens', () => {
        it('should generate access and refresh tokens', async () => {
            const result = await service.issueTokens(mockUser);

            expect(result.access_token).toBeDefined();
            expect(result.refresh_token).toBeDefined();
            expect(result.token_type).toBe('Bearer');
            expect(result.expires_in).toBeGreaterThan(0);
        });
    });

    describe('getJwks', () => {
        it('should return JWKS from key management', async () => {
            const result = await service.getJwks();

            expect(result).toHaveProperty('keys');
            expect(keyManagement.exportJwks).toHaveBeenCalled();
        });
    });

    describe('generateAuthorizationCode', () => {
        it('should generate a valid authorization code', async () => {
            const code = await service.generateAuthorizationCode(
                mockUser,
                'test-client',
                'http://localhost/callback',
                'openid profile'
            );

            expect(code).toBeDefined();
            expect(typeof code).toBe('string');
            expect(code.length).toBe(64); // 32 bytes hex = 64 chars
            expect(blockchainService.addBlock).toHaveBeenCalledWith(
                expect.objectContaining({ event: 'OAUTH_CODE_ISSUED' })
            );
        });
    });
});
