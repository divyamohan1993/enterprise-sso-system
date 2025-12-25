import { Test, TestingModule } from '@nestjs/testing';
import { HealthController } from './health.controller';
import { HealthCheckService, MemoryHealthIndicator } from '@nestjs/terminus';
import { RedisService } from '../common/services/redis.service';

describe('HealthController', () => {
    let controller: HealthController;

    beforeEach(async () => {
        // Mock the health indicators to avoid memory threshold issues in tests
        const mockMemoryIndicator = {
            checkHeap: jest.fn().mockResolvedValue({ memory_heap: { status: 'up' } }),
            checkRSS: jest.fn().mockResolvedValue({ memory_rss: { status: 'up' } }),
        };

        const mockHealthService = {
            check: jest.fn().mockImplementation(async (indicators: (() => Promise<unknown>)[]) => {
                const results = await Promise.all(indicators.map((fn) => fn()));
                return {
                    status: 'ok',
                    info: Object.assign({}, ...results),
                    error: {},
                    details: Object.assign({}, ...results),
                };
            }),
        };

        const mockRedisService = {
            ping: jest.fn().mockResolvedValue(false),
            isAvailable: jest.fn().mockReturnValue(false),
        };

        const module: TestingModule = await Test.createTestingModule({
            controllers: [HealthController],
            providers: [
                { provide: HealthCheckService, useValue: mockHealthService },
                { provide: MemoryHealthIndicator, useValue: mockMemoryIndicator },
                { provide: RedisService, useValue: mockRedisService },
            ],
        }).compile();

        controller = module.get<HealthController>(HealthController);
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });

    describe('check', () => {
        it('should return health status', async () => {
            const result = await controller.check();

            expect(result).toHaveProperty('status');
            expect(result.status).toBe('ok');
        });
    });

    describe('checkReady', () => {
        it('should return readiness status', async () => {
            const result = await controller.checkReady();

            expect(result).toHaveProperty('status');
            expect(result.status).toBe('ok');
        });
    });

    describe('checkStartup', () => {
        it('should return startup status', async () => {
            const result = await controller.checkStartup();

            expect(result).toHaveProperty('status');
            expect(result.status).toBe('ok');
        });
    });

    describe('checkDetailed', () => {
        it('should return detailed health information', async () => {
            const result = await controller.checkDetailed();

            expect(result).toHaveProperty('status');
            expect(result).toHaveProperty('info');
        });
    });
});
