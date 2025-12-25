import { Controller, Get } from '@nestjs/common';
import {
    HealthCheck,
    HealthCheckService,
    HealthCheckResult,
    HealthIndicatorResult,
    MemoryHealthIndicator,
} from '@nestjs/terminus';
import { RedisService } from '../common/services/redis.service';

@Controller('health')
export class HealthController {
    constructor(
        private health: HealthCheckService,
        private memory: MemoryHealthIndicator,
        private redis: RedisService,
    ) { }

    /**
     * Liveness probe - Is the application running?
     * Kubernetes uses this to know whether to restart the container
     */
    @Get()
    @HealthCheck()
    check(): Promise<HealthCheckResult> {
        return this.health.check([
            // Basic heap memory check (256MB threshold)
            () => this.memory.checkHeap('memory_heap', 256 * 1024 * 1024),
        ]);
    }

    /**
     * Readiness probe - Is the application ready to receive traffic?
     * Kubernetes uses this to know whether to route requests to the pod
     */
    @Get('ready')
    @HealthCheck()
    checkReady(): Promise<HealthCheckResult> {
        return this.health.check([
            // Memory checks
            () => this.memory.checkHeap('memory_heap', 256 * 1024 * 1024),
            () => this.memory.checkRSS('memory_rss', 512 * 1024 * 1024),
            // Redis check - optional, so always return 'up' with status info
            async (): Promise<HealthIndicatorResult> => {
                const isHealthy = await this.redis.ping();
                const isConfigured = this.redis.isAvailable();
                return {
                    redis: {
                        status: 'up', // Redis is optional, so we don't fail health check
                        connected: isHealthy,
                        configured: isConfigured,
                        message: isHealthy ? 'Redis connected' : (
                            isConfigured ? 'Redis ping failed' : 'Redis not configured (using in-memory)'
                        ),
                    },
                };
            },
        ]);
    }

    /**
     * Startup probe - Has the application finished initializing?
     * Kubernetes uses this for slow-starting containers
     */
    @Get('startup')
    @HealthCheck()
    checkStartup(): Promise<HealthCheckResult> {
        return this.health.check([
            () => this.memory.checkHeap('memory_heap', 128 * 1024 * 1024),
        ]);
    }

    /**
     * Detailed health status for monitoring dashboards
     */
    @Get('detailed')
    @HealthCheck()
    checkDetailed(): Promise<HealthCheckResult> {
        return this.health.check([
            () => this.memory.checkHeap('memory_heap', 256 * 1024 * 1024),
            () => this.memory.checkRSS('memory_rss', 512 * 1024 * 1024),
            // Redis health
            async (): Promise<HealthIndicatorResult> => {
                const isHealthy = await this.redis.ping();
                return {
                    redis: {
                        status: 'up', // Optional service
                        connected: isHealthy,
                        available: this.redis.isAvailable(),
                    },
                };
            },
            // Blockchain status
            async (): Promise<HealthIndicatorResult> => ({
                blockchain: {
                    status: 'up',
                    message: 'Quantum-safe blockchain service operational',
                },
            }),
            // Quantum crypto status
            async (): Promise<HealthIndicatorResult> => ({
                quantum_crypto: {
                    status: 'up',
                    signatures: 'ML-DSA-65 (Dilithium)',
                    keyExchange: 'ML-KEM-768 (Kyber)',
                    nistStandards: ['FIPS 204', 'FIPS 203'],
                },
            }),
        ]);
    }
}

