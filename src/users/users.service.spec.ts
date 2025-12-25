import { Test, TestingModule } from '@nestjs/testing';
import { UsersService, CreateUserDto } from './users.service';
import { UserRole, UserStatus } from './user.entity';

describe('UsersService', () => {
    let service: UsersService;

    beforeEach(async () => {
        // Clear environment to create fresh admin each test
        delete process.env.ADMIN_INITIAL_PASSWORD;

        const module: TestingModule = await Test.createTestingModule({
            providers: [UsersService],
        }).compile();

        service = module.get<UsersService>(UsersService);
        await service.onModuleInit();
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    describe('create', () => {
        it('should create a new user with hashed password', async () => {
            const dto: CreateUserDto = {
                username: 'newuser',
                email: 'newuser@example.com',
                password: 'SecurePassword123!',
            };

            const user = await service.create(dto);

            expect(user.id).toBeDefined();
            expect(user.username).toBe('newuser');
            expect(user.email).toBe('newuser@example.com');
            expect(user.password).not.toBe(dto.password);
            expect(user.password).toMatch(/^\$argon2/);
            expect(user.roles).toContain(UserRole.USER);
            expect(user.status).toBe(UserStatus.PENDING_VERIFICATION);
        });

        it('should normalize username and email to lowercase', async () => {
            const dto: CreateUserDto = {
                username: 'UserName',
                email: 'User@EXAMPLE.com',
                password: 'SecurePassword123!',
            };

            const user = await service.create(dto);

            expect(user.username).toBe('username');
            expect(user.email).toBe('user@example.com');
        });
    });

    describe('findByUsername', () => {
        it('should find existing user by username', async () => {
            // Admin is created in onModuleInit
            const user = await service.findByUsername('admin');

            expect(user).toBeDefined();
            expect(user?.username).toBe('admin');
        });

        it('should return null for non-existent user', async () => {
            const user = await service.findByUsername('nonexistent');

            expect(user).toBeNull();
        });

        it('should be case-insensitive', async () => {
            const user = await service.findByUsername('ADMIN');

            expect(user).toBeDefined();
            expect(user?.username).toBe('admin');
        });
    });

    describe('validateCredentials', () => {
        it('should reject incorrect password', async () => {
            const result = await service.validateCredentials('admin', 'wrongpassword');

            expect(result.user).toBeNull();
            expect(result.error).toBe('Invalid credentials');
        });

        it('should reject non-existent user', async () => {
            const result = await service.validateCredentials('nonexistent', 'anypassword');

            expect(result.user).toBeNull();
            expect(result.error).toBe('Invalid credentials');
        });
    });

    describe('changePassword', () => {
        it('should change password successfully', async () => {
            const dto: CreateUserDto = {
                username: 'pwchange',
                email: 'pwchange@example.com',
                password: 'OldPassword123!',
            };
            const user = await service.create(dto);
            user.status = UserStatus.ACTIVE;

            const result = await service.changePassword(user, 'NewPassword456!');

            expect(result.success).toBe(true);
        });

        it('should reject password reuse', async () => {
            const dto: CreateUserDto = {
                username: 'pwreuse',
                email: 'pwreuse@example.com',
                password: 'Password123!',
            };
            const user = await service.create(dto);

            // Try to change to same password
            const result = await service.changePassword(user, 'Password123!');

            expect(result.success).toBe(false);
            expect(result.error).toMatch(/Cannot reuse/);
        });
    });

    describe('MFA', () => {
        it('should enable MFA for user', async () => {
            const dto: CreateUserDto = {
                username: 'mfauser',
                email: 'mfauser@example.com',
                password: 'Password123!',
            };
            const user = await service.create(dto);

            await service.enableMfa(user, 'secret123', ['backup1', 'backup2']);

            expect(user.mfaEnabled).toBe(true);
            expect(user.mfaSecret).toBe('secret123');
        });

        it('should disable MFA for user', async () => {
            const dto: CreateUserDto = {
                username: 'mfadisable',
                email: 'mfadisable@example.com',
                password: 'Password123!',
            };
            const user = await service.create(dto);
            await service.enableMfa(user, 'secret', []);

            await service.disableMfa(user);

            expect(user.mfaEnabled).toBe(false);
            expect(user.mfaSecret).toBeNull();
        });
    });
});
